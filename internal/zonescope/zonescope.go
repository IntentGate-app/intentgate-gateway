// Package zonescope enforces per-zone north-south scope: which tools, and in
// which tenants, an agent in a given zone may reach when it calls a tool.
//
// IntentGate already authorizes a single agent-to-tool call through capability
// tokens and policy (north-south), and governs agent-to-agent calls through
// internal/eastwest (east-west). This package adds the zone dimension to the
// north-south half: an ordinary tool call is checked against the caller zone's
// allowlist, so an operator can say "the support zone may only reach the
// read-only tools" once, at the zone level, instead of per agent.
//
// Opt-in per zone. A zone with no configured scope is unrestricted here: the
// agent's own token caveats and the Rego policy still apply, exactly as before.
// A zone WITH a scope is default-deny within that scope: any tool or tenant not
// on the allowlist is denied. This keeps the control additive, turning it on
// for one zone never changes another.
//
// Deterministic and config-driven. The guard holds no per-request state and is
// safe for concurrent use.
package zonescope

import (
	"fmt"
	"sync"
)

// Verdict is the north-south zone decision.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// WildcardAll is the single Tools entry that allows every tool in a zone.
// Use it to declare a zone explicitly unrestricted on tools while still
// constraining tenants.
const WildcardAll = "*"

// Scope is the north-south allowlist for one zone.
type Scope struct {
	// Tools lists the tool names an agent in this zone may call. A single
	// [WildcardAll] ("*") entry allows every tool. An empty Tools list
	// denies every tool: to allow all, list "*" explicitly, so an
	// accidental empty list fails closed rather than open.
	Tools []string
	// Tenants, when non-empty, restricts this zone to those tenant
	// namespaces. Empty means any tenant.
	Tenants []string
}

// Config configures per-zone north-south scope.
type Config struct {
	// Scopes maps a zone id to its allowlist. A zone absent from this map
	// is unrestricted by this guard (the call still passes through the rest
	// of the pipeline).
	Scopes map[string]Scope
}

// Result is the guard's decision plus context, for audit.
type Result struct {
	Verdict Verdict
	Reason  string
	Zone    string
	Tool    string
	// Enforced is true when the zone had a configured scope and was
	// actually evaluated. False means no scope applied to this zone and the
	// Allow is a pass-through, not a decision.
	Enforced bool
}

// Guard evaluates north-south tool calls against the configured zone scopes.
// Safe for concurrent use.
type Guard struct {
	mu     sync.RWMutex
	scopes map[string]compiledScope
	cfg    Config // retained for Snapshot (read-only surfaces)
}

type compiledScope struct {
	allowAllTools bool
	tools         map[string]bool
	tenants       map[string]bool // empty => any tenant
}

// New returns a Guard for the given config.
func New(cfg Config) *Guard {
	scopes := make(map[string]compiledScope, len(cfg.Scopes))
	for zone, s := range cfg.Scopes {
		cs := compiledScope{
			tools:   make(map[string]bool, len(s.Tools)),
			tenants: make(map[string]bool, len(s.Tenants)),
		}
		for _, tool := range s.Tools {
			if tool == WildcardAll {
				cs.allowAllTools = true
				continue
			}
			cs.tools[tool] = true
		}
		for _, tenant := range s.Tenants {
			cs.tenants[tenant] = true
		}
		scopes[zone] = cs
	}
	return &Guard{scopes: scopes, cfg: cfg}
}

// Snapshot returns a deep copy of the guard's configuration, for read-only
// surfaces that render the current segmentation. Mutating the result does not
// affect the guard.
func (g *Guard) Snapshot() Config {
	out := Config{}
	if g.cfg.Scopes != nil {
		out.Scopes = make(map[string]Scope, len(g.cfg.Scopes))
		for zone, s := range g.cfg.Scopes {
			cp := Scope{}
			if s.Tools != nil {
				cp.Tools = append([]string(nil), s.Tools...)
			}
			if s.Tenants != nil {
				cp.Tenants = append([]string(nil), s.Tenants...)
			}
			out.Scopes[zone] = cp
		}
	}
	return out
}

// Check decides whether an agent in the given zone may call tool within tenant.
// A zone with no configured scope yields Allow with Enforced=false, so the
// caller can treat it as a pass-through.
func (g *Guard) Check(zone, tenant, tool string) Result {
	g.mu.RLock()
	s, ok := g.scopes[zone]
	g.mu.RUnlock()
	if !ok {
		return Result{Verdict: VerdictAllow, Enforced: false, Zone: zone, Tool: tool}
	}

	res := Result{Zone: zone, Tool: tool, Enforced: true}

	if len(s.tenants) > 0 && !s.tenants[tenant] {
		res.Verdict = VerdictDeny
		res.Reason = fmt.Sprintf("zone %q is not permitted in tenant %q", zone, tenant)
		return res
	}

	if s.allowAllTools || s.tools[tool] {
		res.Verdict = VerdictAllow
		res.Reason = fmt.Sprintf("tool %q permitted for zone %q", tool, zone)
		return res
	}

	res.Verdict = VerdictDeny
	res.Reason = fmt.Sprintf("tool %q is not in the north-south scope for zone %q", tool, zone)
	return res
}
