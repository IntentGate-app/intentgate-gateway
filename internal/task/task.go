// Package task implements task-level intent binding (goal-drift
// detection): the eighth-domain control that binds a whole multi-step
// agent task to the plan it declared at the start, and flags or blocks
// the session when its trajectory drifts off that plan.
//
// # Why it exists
//
// The per-call intent check (internal/extractor + the intent stage in
// the MCP handler) answers "does THIS call match the stated purpose?".
// It cannot see the shape of a whole task. An agent can take a series of
// individually-permitted, individually-plausible steps that together
// accomplish something the user never asked for — the "excessive agency"
// / goal-hijack class (OWASP AAI06). No single call fails; the
// trajectory is wrong. Task binding reads the trajectory.
//
// # How it works
//
// A task is a sequence of calls sharing a stable task id (the
// X-Task-Id header). On the first call the gateway captures the task's
// declared plan — the extractor's allowed_tools for the task — as the
// envelope. On every subsequent call the binder updates the running
// trajectory (calls made, distinct tools used) and accumulates a drift
// score: calls to tools outside the declared plan, growth in distinct
// tools beyond the plan, and running past a call budget each add to it.
// Two thresholds turn the score into an action: warn (flag and audit,
// allow the call) and block (deny the call).
//
// The signal is deterministic and explainable — every increment points
// at a concrete off-plan call or a budget overrun, not a model's guess.
// Semantic drift beyond the declared plan (an LLM-judge layer) is a
// later phase; this package is the deterministic core.
package task

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is the lifecycle state of a bound task.
type Status string

const (
	// StatusActive: within plan and budget.
	StatusActive Status = "active"
	// StatusFlagged: drift crossed the warn threshold; calls still allowed.
	StatusFlagged Status = "flagged"
	// StatusHalted: drift crossed the block threshold; calls are denied.
	StatusHalted Status = "halted"
)

// Task is the persisted state of one bound task.
type Task struct {
	ID        string    `json:"id"`
	Tenant    string    `json:"tenant,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	Intent    string    `json:"intent,omitempty"` // declared task summary
	Plan      []string  `json:"plan,omitempty"`   // declared allowed tools (the envelope)
	Tools     []string  `json:"tools,omitempty"`  // distinct tools actually used
	Calls     int       `json:"calls"`
	Drift     int       `json:"drift"`
	Status    Status    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Outcome is the binder's decision for a single call.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeFlag  Outcome = "flag"
	OutcomeBlock Outcome = "block"
)

// BindResult is what the binder returns for one call.
type BindResult struct {
	Outcome Outcome
	Drift   int
	Reason  string
	Task    *Task
}

// Config holds the drift thresholds. All are env-tunable at startup so
// the baseline fits how a deployment's agents actually run.
type Config struct {
	Enabled bool
	// MaxCalls is the per-task call budget; calls beyond it add drift.
	MaxCalls int
	// PlanSlack is how many distinct tools beyond the declared plan size
	// are tolerated before distinct-tool growth adds drift.
	PlanSlack int
	// OffPlanWeight is drift added for a call to a tool outside the plan.
	OffPlanWeight int
	// OverBudgetWeight is drift added once past MaxCalls.
	OverBudgetWeight int
	// DistinctWeight is drift added once distinct tools exceed plan+slack.
	DistinctWeight int
	// WarnScore flags the task (audit, still allow).
	WarnScore int
	// BlockScore halts the task (deny the call).
	BlockScore int
}

// DefaultConfig returns conservative thresholds. Off-plan calls are the
// strongest signal; a single one flags, three block by default.
func DefaultConfig() Config {
	return Config{
		Enabled:          false,
		MaxCalls:         50,
		PlanSlack:        2,
		OffPlanWeight:    3,
		OverBudgetWeight: 2,
		DistinctWeight:   2,
		WarnScore:        3,
		BlockScore:       9,
	}
}

// Store persists task state. Implementations MUST be safe for concurrent
// use: Get/Upsert are on the request path.
type Store interface {
	// Get returns the task or (nil, nil) if none exists for (tenant, id).
	Get(ctx context.Context, tenant, id string) (*Task, error)
	// Upsert persists the task.
	Upsert(ctx context.Context, t *Task) error
	// List returns recent tasks, most-recently-updated first, filtered by
	// tenant ("" = all, superadmin view).
	List(ctx context.Context, tenant string, limit, offset int) ([]*Task, error)
}

// Binder applies the drift model over a Store.
type Binder struct {
	store Store
	cfg   Config
}

// NewBinder constructs a Binder. A nil store or a disabled config makes
// Bind a no-op that always allows.
func NewBinder(store Store, cfg Config) *Binder {
	return &Binder{store: store, cfg: cfg}
}

// Enabled reports whether binding is active.
func (b *Binder) Enabled() bool {
	return b != nil && b.store != nil && b.cfg.Enabled
}

// Bind records a call against its task and returns the drift decision.
//
// taskID is the X-Task-Id header; an empty taskID (or a disabled binder)
// is a no-op allow. plan is the declared allowed_tools captured from the
// extractor at task start; summary is the declared task summary. On the
// first call for a task id the plan/summary are stored as the envelope;
// later calls reuse the stored envelope (the passed plan is ignored once
// set, so an agent cannot widen its own plan mid-task).
func (b *Binder) Bind(ctx context.Context, tenant, agent, taskID, tool string, plan []string, summary string) (BindResult, error) {
	if !b.Enabled() || strings.TrimSpace(taskID) == "" {
		return BindResult{Outcome: OutcomeAllow}, nil
	}

	now := time.Now().UTC()
	t, err := b.store.Get(ctx, tenant, taskID)
	if err != nil {
		return BindResult{Outcome: OutcomeAllow}, err
	}
	if t == nil {
		// First call: establish the envelope from the declared plan.
		t = &Task{
			ID:        taskID,
			Tenant:    tenant,
			Agent:     agent,
			Intent:    summary,
			Plan:      dedup(plan),
			Status:    StatusActive,
			StartedAt: now,
		}
	}

	// If the task was already halted, keep blocking without re-scoring —
	// a halted task stays halted until an operator clears it.
	if t.Status == StatusHalted {
		t.UpdatedAt = now
		_ = b.store.Upsert(ctx, t)
		return BindResult{Outcome: OutcomeBlock, Drift: t.Drift, Reason: "task halted by earlier drift", Task: t}, nil
	}

	t.Calls++
	if !contains(t.Tools, tool) {
		t.Tools = append(t.Tools, tool)
	}

	// Score this call.
	delta := 0
	var reasons []string
	if len(t.Plan) > 0 && !contains(t.Plan, tool) {
		delta += b.cfg.OffPlanWeight
		reasons = append(reasons, "off-plan tool "+tool)
	}
	if b.cfg.MaxCalls > 0 && t.Calls > b.cfg.MaxCalls {
		delta += b.cfg.OverBudgetWeight
		reasons = append(reasons, "over call budget")
	}
	limit := b.cfg.PlanSlack
	if len(t.Plan) > 0 {
		limit = len(t.Plan) + b.cfg.PlanSlack
	}
	if limit > 0 && len(t.Tools) > limit {
		delta += b.cfg.DistinctWeight
		reasons = append(reasons, "distinct-tool growth")
	}
	t.Drift += delta
	t.UpdatedAt = now

	out := OutcomeAllow
	switch {
	case b.cfg.BlockScore > 0 && t.Drift >= b.cfg.BlockScore:
		t.Status = StatusHalted
		out = OutcomeBlock
	case b.cfg.WarnScore > 0 && t.Drift >= b.cfg.WarnScore:
		if t.Status == StatusActive {
			t.Status = StatusFlagged
		}
		out = OutcomeFlag
	}

	if err := b.store.Upsert(ctx, t); err != nil {
		// Persist failure shouldn't take down the request path; log-and-allow
		// is safer than fail-closed here because binding is advisory drift,
		// not a hard authorization gate. The caller decides.
		return BindResult{Outcome: out, Drift: t.Drift, Reason: strings.Join(reasons, "; "), Task: t}, err
	}
	return BindResult{Outcome: out, Drift: t.Drift, Reason: strings.Join(reasons, "; "), Task: t}, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func dedup(xs []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// MemoryStore is a process-local task store. Single-replica; lost on
// restart. Fine for dev and single-node installs.
type MemoryStore struct {
	mu    sync.RWMutex
	tasks map[string]*Task // key: tenant|id
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{tasks: make(map[string]*Task)}
}

func memKey(tenant, id string) string { return tenant + "|" + id }

func (s *MemoryStore) Get(_ context.Context, tenant, id string) (*Task, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[memKey(tenant, id)]
	if !ok {
		return nil, nil
	}
	cp := *t // return a copy so callers can't mutate stored state
	return &cp, nil
}

func (s *MemoryStore) Upsert(_ context.Context, t *Task) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *t
	s.tasks[memKey(t.Tenant, t.ID)] = &cp
	return nil
}

func (s *MemoryStore) List(_ context.Context, tenant string, limit, offset int) ([]*Task, error) {
	s.mu.RLock()
	out := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		if tenant != "" && t.Tenant != tenant {
			continue
		}
		cp := *t
		out = append(out, &cp)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if offset > len(out) {
		return []*Task{}, nil
	}
	out = out[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
