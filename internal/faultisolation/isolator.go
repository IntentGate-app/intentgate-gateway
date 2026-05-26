// Package faultisolation contains the per-tool circuit breaker and
// bulkhead (semaphore) the gateway runs in front of the upstream
// forward step.
//
// Threat closed (OWASP Agentic AI AGENT08 — Cascading Failures):
// one slow or failing tool (a database that's locking up, a vector
// store that's returning 500s) can monopolize the gateway's goroutine
// pool and its connection budget to the upstream — every healthy
// tool inherits the slow tool's pain and the entire agent layer
// degrades together. The fault-isolation layer bounds the blast
// radius of a single tool to that tool only.
//
// Two independent mechanisms:
//
//  1. BULKHEAD — per-tool semaphore. A capacity of N means at most
//     N concurrent forwards to that tool. Excess callers either
//     wait for a permit (queue=true) or fail-fast with the
//     "bulkhead full" error (queue=false). A misbehaving tool can
//     fill its own slots but cannot starve another tool's.
//
//  2. CIRCUIT BREAKER — per-tool state machine. After consecutive
//     failures cross the threshold, the breaker opens: subsequent
//     calls fail-fast with the "circuit open" error for the
//     cooldown window. The first probe after cooldown enters
//     half-open; if it succeeds the breaker closes, if it fails
//     the cooldown is reset.
//
// Both mechanisms are per-tool. A breaker open on tool A has no
// effect on calls to tool B. A bulkhead full for tool A still lets
// tool B run at its own capacity.
//
// Configuration:
//
//   - INTENTGATE_FAULT_ISOLATION_ENABLED — "true" to wire the layer.
//     When false (default), every call is a passthrough.
//   - INTENTGATE_FAULT_ISOLATION_MAX_CONCURRENT_PER_TOOL — semaphore
//     capacity. Default 20 (matches the upstream client's pool size).
//   - INTENTGATE_FAULT_ISOLATION_FAILURE_THRESHOLD — consecutive
//     failures that trip the breaker. Default 5.
//   - INTENTGATE_FAULT_ISOLATION_COOLDOWN_MS — open-state duration
//     in milliseconds. Default 30000 (30s).
//
// State is process-local. In a multi-replica deployment each replica
// maintains its own breaker — typical for circuit-breaker patterns,
// and the failure surface is per-replica anyway (a process that
// can't reach the upstream from one host may still be reachable
// from another).
package faultisolation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// State is the current circuit-breaker phase for a tool.
type State int

const (
	// StateClosed = normal. Calls pass through, failures accumulate.
	StateClosed State = iota
	// StateOpen = tripped. Calls fail-fast for the cooldown window.
	StateOpen
	// StateHalfOpen = probing. One call passes; if it succeeds the
	// breaker closes, if it fails the cooldown resets.
	StateHalfOpen
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// Sentinel errors returned by Allow when the gateway should fail-fast
// rather than calling the upstream.
var (
	// ErrCircuitOpen is returned when the breaker for a tool is open.
	// Callers translate this into CodeUpstreamCircuitOpen (-32018).
	ErrCircuitOpen = errors.New("faultisolation: circuit open")
	// ErrBulkheadFull is returned when the per-tool semaphore has no
	// permits available. Callers translate this into the same code
	// with a different reason field — the agent doesn't need to
	// distinguish them in JSON-RPC, but the audit row does.
	ErrBulkheadFull = errors.New("faultisolation: bulkhead full")
)

// Config holds the parameters that shape the isolator's behaviour.
// Zero values fall back to sensible defaults documented per-field.
type Config struct {
	// MaxConcurrentPerTool is the bulkhead semaphore size. Zero/neg
	// disables the bulkhead (only the breaker runs).
	MaxConcurrentPerTool int
	// FailureThreshold is the number of consecutive failures that
	// trips the breaker. Zero/neg disables the breaker (only the
	// bulkhead runs).
	FailureThreshold int
	// Cooldown is how long the breaker stays open before allowing a
	// half-open probe. Zero falls back to 30s.
	Cooldown time.Duration
}

// applyDefaults mutates cfg in place, replacing zero/neg fields with
// the documented defaults.
func (c *Config) applyDefaults() {
	if c.MaxConcurrentPerTool <= 0 {
		c.MaxConcurrentPerTool = 20
	}
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 5
	}
	if c.Cooldown <= 0 {
		c.Cooldown = 30 * time.Second
	}
}

// Isolator is the per-tool fault-isolation enforcer. Construct one
// with [New] at startup and call [Acquire] before every upstream
// forward.
type Isolator struct {
	cfg   Config
	state sync.Map // tool name -> *toolState
	// now is the clock source. Overridable for tests; defaults to
	// time.Now.
	now func() time.Time
}

// toolState bundles the per-tool state. All fields are read/written
// under mu — no lock-free shortcuts. Atomic counters track running
// permits to avoid a hot path through the same mutex on every
// permit acquire.
type toolState struct {
	name string

	mu sync.Mutex
	// state is the breaker phase. Guarded by mu.
	state State
	// consecutiveFailures is reset on success.
	consecutiveFailures int
	// openedAt is the timestamp at which the breaker last opened.
	// Used to compute when the half-open probe is allowed.
	openedAt time.Time

	// inFlight counts active permits (atomic for read on the hot
	// path; written under mu). Acquire/Release follow the standard
	// CAS-loop semaphore pattern.
	inFlight atomic.Int32
}

// New returns an Isolator with the given config.
func New(cfg Config) *Isolator {
	cfg.applyDefaults()
	return &Isolator{
		cfg: cfg,
		now: time.Now,
	}
}

// stateFor returns (and lazily allocates) the per-tool state.
func (i *Isolator) stateFor(tool string) *toolState {
	if v, ok := i.state.Load(tool); ok {
		return v.(*toolState)
	}
	ts := &toolState{name: tool}
	actual, _ := i.state.LoadOrStore(tool, ts)
	return actual.(*toolState)
}

// Acquire is the gate before an upstream forward.
//
//   - Returns (release, nil) when the call may proceed. The caller
//     MUST call release() with the success/failure outcome when the
//     forward completes (whether it succeeded or not).
//   - Returns (nil, ErrCircuitOpen) when the breaker is open.
//   - Returns (nil, ErrBulkheadFull) when no semaphore permits remain.
//
// Both error cases are fail-fast (no waiting). Operators who want
// queueing should add it at a higher layer; the gateway's contract
// with the agent is "fast no" or "complete answer" — slow queues are
// a worse failure mode than fail-fast for an LLM caller that may
// also be on a timeout.
func (i *Isolator) Acquire(ctx context.Context, tool string) (release func(outcome Outcome), err error) {
	if i == nil {
		return func(Outcome) {}, nil
	}
	ts := i.stateFor(tool)

	// Breaker.
	if i.cfg.FailureThreshold > 0 {
		ts.mu.Lock()
		switch ts.state {
		case StateOpen:
			elapsed := i.now().Sub(ts.openedAt)
			if elapsed < i.cfg.Cooldown {
				ts.mu.Unlock()
				return nil, ErrCircuitOpen
			}
			// Cooldown elapsed → transition to half-open. Only one
			// probe is permitted; that probe is exactly this call.
			ts.state = StateHalfOpen
		case StateHalfOpen:
			// Another probe is already in flight. Treat as still-open
			// for this caller — only one probe per cooldown.
			ts.mu.Unlock()
			return nil, ErrCircuitOpen
		}
		ts.mu.Unlock()
	}

	// Bulkhead.
	if i.cfg.MaxConcurrentPerTool > 0 {
		for {
			cur := ts.inFlight.Load()
			if int(cur) >= i.cfg.MaxConcurrentPerTool {
				return nil, ErrBulkheadFull
			}
			if ts.inFlight.CompareAndSwap(cur, cur+1) {
				break
			}
		}
	}

	return func(outcome Outcome) {
		if i.cfg.MaxConcurrentPerTool > 0 {
			ts.inFlight.Add(-1)
		}
		i.record(ts, outcome)
	}, nil
}

// record updates the breaker state based on the call outcome.
func (i *Isolator) record(ts *toolState, outcome Outcome) {
	if i.cfg.FailureThreshold <= 0 {
		return
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	switch outcome {
	case OutcomeSuccess:
		ts.consecutiveFailures = 0
		if ts.state == StateHalfOpen || ts.state == StateOpen {
			ts.state = StateClosed
		}
	case OutcomeFailure:
		ts.consecutiveFailures++
		if ts.state == StateHalfOpen {
			// Probe failed → re-open the breaker, reset cooldown.
			ts.state = StateOpen
			ts.openedAt = i.now()
			return
		}
		if ts.state == StateClosed && ts.consecutiveFailures >= i.cfg.FailureThreshold {
			ts.state = StateOpen
			ts.openedAt = i.now()
		}
	case OutcomeIgnore:
		// Don't move the breaker. Used for cases like a client-side
		// validation failure where the upstream wasn't called.
	}
}

// Outcome describes the result of the gated call. Pass to the
// release function returned by Acquire.
type Outcome int

const (
	OutcomeSuccess Outcome = iota
	OutcomeFailure
	OutcomeIgnore
)

// Snapshot returns a copy of the per-tool state for telemetry /
// admin endpoints. Safe to call from any goroutine.
type Snapshot struct {
	Tool                string
	State               State
	ConsecutiveFailures int
	InFlight            int32
	OpenedAt            time.Time
}

// Snapshot returns the current state for one tool. Empty Snapshot
// when the tool hasn't been touched yet.
func (i *Isolator) Snapshot(tool string) Snapshot {
	if i == nil {
		return Snapshot{Tool: tool}
	}
	v, ok := i.state.Load(tool)
	if !ok {
		return Snapshot{Tool: tool}
	}
	ts := v.(*toolState)
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return Snapshot{
		Tool:                tool,
		State:               ts.state,
		ConsecutiveFailures: ts.consecutiveFailures,
		InFlight:            ts.inFlight.Load(),
		OpenedAt:            ts.openedAt,
	}
}

// SnapshotAll returns a snapshot for every tool the isolator has
// touched. Useful for an admin endpoint or a Prometheus collector.
func (i *Isolator) SnapshotAll() []Snapshot {
	if i == nil {
		return nil
	}
	var out []Snapshot
	i.state.Range(func(key, value any) bool {
		ts := value.(*toolState)
		ts.mu.Lock()
		out = append(out, Snapshot{
			Tool:                key.(string),
			State:               ts.state,
			ConsecutiveFailures: ts.consecutiveFailures,
			InFlight:            ts.inFlight.Load(),
			OpenedAt:            ts.openedAt,
		})
		ts.mu.Unlock()
		return true
	})
	return out
}

// FormatStateForLog returns a stable single-line summary for slog.
func (s Snapshot) FormatStateForLog() string {
	return fmt.Sprintf("tool=%s state=%s in_flight=%d consec_failures=%d",
		s.Tool, s.State, s.InFlight, s.ConsecutiveFailures)
}
