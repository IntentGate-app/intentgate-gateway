// Package riskregister feeds IntentGate's runtime enforcement outcomes into
// an enterprise risk register (GRC/IRM) as continuous, automated risk
// indicators and issues — so a risk officer sees an agent's residual risk
// move in real time instead of filling in a quarterly survey.
//
// # Vendor-agnostic by design
//
// The enforcement core never talks to a risk register directly. It emits
// audit events; a single [Exporter] seam is the only thing a concrete risk
// register (ServiceNow IRM today, OneTrust or MetricStream tomorrow) plugs
// into. Adding a vendor is one file implementing [Exporter] — the
// aggregator, the wiring, and the non-blocking contract stay unchanged.
//
// # Non-blocking, zero-payload
//
// [Aggregator] implements [audit.Emitter]: Emit only bumps in-memory
// counters (never blocks the request path), and a background ticker turns
// each 1-minute window into rollups the Exporter pushes asynchronously. If
// the risk register is slow or down, inline enforcement is unaffected — the
// window is simply exported late or dropped, never queued in front of an
// agent's call. Only counts, decision codes, and hashes leave the boundary;
// prompts, arguments, and results never do.
package riskregister

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// Exporter is the single seam every risk register implements. Both calls
// run on the background flush goroutine (never the request path), so a
// blocking HTTP round trip here is fine.
type Exporter interface {
	// Name is a short identifier used in logs ("servicenow", "onetrust").
	Name() string
	// PushIndicators sends one window's per-agent rollups as automated risk
	// indicators. Called once per flush with every agent seen in the window.
	PushIndicators(ctx context.Context, indicators []RiskIndicator) error
	// OpenIssue raises a risk issue when an agent breaches the block
	// threshold in a window. Called per breaching agent, after the
	// indicators for the same window.
	OpenIssue(ctx context.Context, issue RiskIssue) error
}

// RiskIndicator is one agent's decision rollup over a single window — the
// vendor-neutral shape each Exporter maps onto its own indicator API.
type RiskIndicator struct {
	Tenant      string
	AgentID     string
	WindowStart time.Time
	WindowEnd   time.Time
	Allow       int
	Deny        int
	Escalate    int
	Total       int
}

// BlockRate is Deny/Total in [0,1]; 0 when the window had no decisions.
func (r RiskIndicator) BlockRate() float64 {
	if r.Total == 0 {
		return 0
	}
	return float64(r.Deny) / float64(r.Total)
}

// RiskIssue is a threshold breach worth a tracked issue in the register.
type RiskIssue struct {
	Tenant      string
	AgentID     string
	Category    string
	Reason      string
	ProofSHA256 string
	DenyCount   int
	WindowStart time.Time
	WindowEnd   time.Time
}

// Config tunes the aggregator.
type Config struct {
	// FlushInterval is the rollup window. Default 60s.
	FlushInterval time.Duration
	// BlockThreshold is the number of DENY decisions for one agent in a
	// single window that opens a risk issue. 0 disables issue creation
	// (indicators still flow). Default 0.
	BlockThreshold int
	// Logger receives export-error notices. nil falls back to slog.Default.
	Logger *slog.Logger
	// FlushTimeout caps each export round trip. Default 30s.
	FlushTimeout time.Duration
}

const (
	defaultFlushInterval = time.Minute
	defaultFlushTimeout  = 30 * time.Second
)

type key struct{ tenant, agent string }

type bucket struct {
	allow, deny, escalate int
	lastReason            string
	lastProof             string
}

// Aggregator counts decisions per agent per window and, on a ticker,
// exports the window's rollups (and any threshold breaches) via the
// configured Exporter. It is an [audit.Emitter], so it drops straight into
// the gateway's existing fan-out.
type Aggregator struct {
	exporter    Exporter
	cfg         Config
	mu          sync.Mutex
	windowStart time.Time
	counts      map[key]*bucket
	closed      atomic.Bool
	stop        chan struct{}
	wg          sync.WaitGroup
	log         *slog.Logger
}

// NewAggregator builds the aggregator and starts its flush loop.
func NewAggregator(exp Exporter, cfg Config) *Aggregator {
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.FlushTimeout <= 0 {
		cfg.FlushTimeout = defaultFlushTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Aggregator{
		exporter:    exp,
		cfg:         cfg,
		counts:      make(map[key]*bucket),
		windowStart: time.Now(),
		stop:        make(chan struct{}),
		log:         cfg.Logger,
	}
	a.wg.Add(1)
	go a.run()
	return a
}

// Emit records one decision. In-memory only — never blocks the caller.
func (a *Aggregator) Emit(_ context.Context, e audit.Event) {
	if a == nil || a.closed.Load() {
		return
	}
	agent := e.AgentID
	if agent == "" {
		agent = "(unknown)"
	}
	k := key{tenant: e.Tenant, agent: agent}

	a.mu.Lock()
	b := a.counts[k]
	if b == nil {
		b = &bucket{}
		a.counts[k] = b
	}
	switch e.Decision {
	case audit.DecisionBlock:
		b.deny++
		if e.Reason != "" {
			b.lastReason = e.Reason
		}
		if e.ResultSHA256 != "" {
			b.lastProof = e.ResultSHA256
		}
	case audit.DecisionEscalate:
		b.escalate++
	default:
		b.allow++
	}
	a.mu.Unlock()
}

// Stop halts the flush loop after one final flush. Safe to call once.
func (a *Aggregator) Stop(ctx context.Context) error {
	if !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(a.stop)
	done := make(chan struct{})
	go func() { a.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Aggregator) run() {
	defer a.wg.Done()
	t := time.NewTicker(a.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			a.flush()
		case <-a.stop:
			a.flush()
			return
		}
	}
}

// flush snapshots and resets the window, then exports indicators and any
// threshold issues. Runs on the background goroutine, so the export round
// trips here never touch the request path.
func (a *Aggregator) flush() {
	a.mu.Lock()
	start := a.windowStart
	end := time.Now()
	snap := a.counts
	a.counts = make(map[key]*bucket)
	a.windowStart = end
	a.mu.Unlock()

	if len(snap) == 0 {
		return
	}

	indicators := make([]RiskIndicator, 0, len(snap))
	var issues []RiskIssue
	for k, b := range snap {
		total := b.allow + b.deny + b.escalate
		indicators = append(indicators, RiskIndicator{
			Tenant:      k.tenant,
			AgentID:     k.agent,
			WindowStart: start,
			WindowEnd:   end,
			Allow:       b.allow,
			Deny:        b.deny,
			Escalate:    b.escalate,
			Total:       total,
		})
		if a.cfg.BlockThreshold > 0 && b.deny >= a.cfg.BlockThreshold {
			issues = append(issues, RiskIssue{
				Tenant:      k.tenant,
				AgentID:     k.agent,
				Category:    "AI runtime policy breach",
				Reason:      b.lastReason,
				ProofSHA256: b.lastProof,
				DenyCount:   b.deny,
				WindowStart: start,
				WindowEnd:   end,
			})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.FlushTimeout)
	defer cancel()

	if err := a.exporter.PushIndicators(ctx, indicators); err != nil {
		a.log.Warn("riskregister: push indicators failed",
			"exporter", a.exporter.Name(), "agents", len(indicators), "err", err)
	}
	for _, is := range issues {
		if err := a.exporter.OpenIssue(ctx, is); err != nil {
			a.log.Warn("riskregister: open issue failed",
				"exporter", a.exporter.Name(), "agent", is.AgentID, "err", err)
		}
	}
}
