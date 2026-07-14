// Package actionguard is the effect-level enforcement layer that sits in front
// of the Rego policy stage. It resolves every tool call to an Action IR (via
// internal/actionir) and applies two classes of deterministic control that a
// per-call string policy cannot express:
//
//  1. Mandatory hold (Phase 1): irreversible, high-value, or unbounded
//     destructive actions cannot silently proceed. They are blocked or paused
//     for human approval regardless of what any customer policy says. This is a
//     fail-safe backstop, not a suggestion.
//
//  2. Plan-level correlation (#28): the guard keeps per-session history of
//     resolved actions, so it can catch a chain of individually-legal steps
//     that together are harmful. The flagship rule is invoice-fraud style: a
//     payment to a party that the same agent created earlier in the session.
//
// Everything here is deterministic: the same session history and call always
// yield the same verdict. No model is consulted.
//
// The handler calls Check before the capability/intent/policy/budget pipeline.
// A Block or Escalate short-circuits; an Allow falls through to the existing
// checks (which may still block for other reasons).
package actionguard

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// Verdict is actionguard's decision. It maps onto the gateway's existing
// allow / block / escalate semantics (escalate == pause for human approval).
type Verdict string

const (
	VerdictAllow    Verdict = "allow"
	VerdictBlock    Verdict = "block"
	VerdictEscalate Verdict = "escalate"
)

// Result is the guard's verdict plus the resolved IR and which rule fired.
type Result struct {
	Verdict Verdict
	Reason  string
	Rule    string // stable identifier of the rule that fired, "" on allow
	IR      actionir.ActionIR
}

// Config tunes the mandatory-hold thresholds. Zero values disable a rule.
type Config struct {
	// EscalateOverCents: an irreversible action moving at least this much
	// money pauses for human approval. 0 disables.
	EscalateOverCents int64
	// BlockUnboundedDelete: an unbounded (no-filter / wildcard / "all")
	// delete is blocked outright.
	BlockUnboundedDelete bool
	// Feed is an optional threat-intel feed of known-bad indicators, evaluated
	// before the mandatory-hold and plan-level rules. nil disables it.
	Feed *ThreatFeed
}

// DefaultConfig is a sensible starting point: hold irreversible actions over
// EUR 5,000 and block unbounded deletes.
func DefaultConfig() Config {
	return Config{EscalateOverCents: 500000, BlockUnboundedDelete: true}
}

// Guard holds per-session state for plan-level correlation. Safe for
// concurrent use.
type Guard struct {
	cfg      Config
	feed     *ThreatFeed
	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	// created holds normalised names of parties/resources the agent created
	// during this session (suppliers, vendors, accounts). Used to catch a
	// later payment to a just-created party.
	created map[string]bool
	// history is the ordered list of resolved actions in this session.
	history []actionir.ActionIR
}

// New returns a Guard with the given config.
func New(cfg Config) *Guard {
	return &Guard{cfg: cfg, feed: cfg.Feed, sessions: make(map[string]*session)}
}

var reSpace = regexp.MustCompile(`\s+`)

func norm(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(strings.ToLower(s), " "))
}

// Check resolves the call, evaluates the plan-level and mandatory-hold rules
// against this session's history, records the action, and returns a verdict.
func (g *Guard) Check(sessionID, tool string, args map[string]any) Result {
	ir := actionir.Resolve(tool, args)

	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sessions[sessionID]
	if s == nil {
		s = &session{created: make(map[string]bool)}
		g.sessions[sessionID] = s
	}

	// Rule 0 (threat-intel feed): known-bad destination, tool, or sequence.
	// Evaluated first so a fresh indicator catches an attack the other rules
	// would let through.
	if g.feed != nil {
		if v, reason, rule, hit := g.feed.match(tool, ir, s.history); hit {
			g.record(s, ir, args)
			return Result{v, reason, rule, ir}
		}
	}

	// Rule 1 (mandatory hold): unbounded destructive action is blocked.
	if g.cfg.BlockUnboundedDelete && ir.Op == actionir.OpDelete && ir.Scope == actionir.ScopeUnbounded {
		g.record(s, ir, args)
		return Result{VerdictBlock, "unbounded delete is not permitted", "hold.unbounded_delete", ir}
	}

	// Rule 2 (plan-level #28): payment to a party this agent created earlier
	// in the same session. The invoice-fraud chain: create supplier, then pay.
	if ir.Op == actionir.OpPay && ir.Destination != "" && s.created[norm(ir.Destination)] {
		g.record(s, ir, args)
		return Result{
			VerdictEscalate,
			fmt.Sprintf("payment to %q, a party created earlier in this session", ir.Destination),
			"plan.pay_to_self_created_party", ir,
		}
	}

	// Rule 3 (mandatory hold): irreversible, high-value action pauses for a human.
	if !ir.Reversible && g.cfg.EscalateOverCents > 0 && ir.MagnitudeCents >= g.cfg.EscalateOverCents {
		g.record(s, ir, args)
		return Result{
			VerdictEscalate,
			fmt.Sprintf("irreversible action of %d cents requires human approval", ir.MagnitudeCents),
			"hold.high_value_irreversible", ir,
		}
	}

	g.record(s, ir, args)
	return Result{VerdictAllow, "", "", ir}
}

// record appends the action to session history and, for create actions, tracks
// the created party's name so a later payment to it can be correlated.
func (g *Guard) record(s *session, ir actionir.ActionIR, args map[string]any) {
	s.history = append(s.history, ir)
	if ir.Op == actionir.OpCreate {
		for _, name := range createdNames(ir, args) {
			if name != "" {
				s.created[norm(name)] = true
			}
		}
	}
}

// createdNames pulls the name of a just-created entity from the IR destination
// and from common name-bearing args (create_supplier{name:...}).
func createdNames(ir actionir.ActionIR, args map[string]any) []string {
	out := []string{}
	if ir.Destination != "" {
		out = append(out, ir.Destination)
	}
	for k, v := range args {
		lk := strings.ToLower(k)
		if lk == "name" || lk == "supplier" || lk == "vendor" || lk == "payee" || lk == "beneficiary" {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// Forget drops a session's state (call on session end to bound memory).
func (g *Guard) Forget(sessionID string) {
	g.mu.Lock()
	delete(g.sessions, sessionID)
	g.mu.Unlock()
}
