// Package eastwest authorizes agent-to-agent (east-west) calls.
//
// IntentGate's normal pipeline authorizes an agent calling a tool
// (north-south). This package adds control over one agent calling ANOTHER
// agent (east-west), which is where confused-deputy and lateral-spread risks
// live in multi-agent systems.
//
// Model: agent-as-tool. An agent reaches another agent by calling it as a tool
// through the gateway, so the inter-agent call passes the same enforcement
// point as every other call. A tool named "<prefix><agent-id>" (for example
// "agent:finance") is treated as a call to that agent.
//
// Decision: a zone model plus default-deny. Each agent belongs to a zone. An
// agent may call another agent only when an explicit edge permits the path
// from the caller's zone to the callee's zone, or when both are in the same
// zone and intra-zone calls are allowed. Anything else is denied. This is the
// containment control: it keeps a compromised agent from recruiting agents in
// other zones.
//
// Deterministic and config-driven. A call that is NOT an agent-to-agent call
// is a no-op here and passes straight through, so wiring this in front of the
// pipeline never affects ordinary tool traffic.
package eastwest

import (
	"fmt"
	"strings"
	"sync"
)

// Verdict is the east-west decision.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Config configures east-west authorization. The zero value is inert: with no
// AgentToolPrefix, nothing is treated as an agent-to-agent call.
type Config struct {
	// AgentToolPrefix marks a tool call as an agent-to-agent call. A tool
	// named "<prefix><agent-id>" targets another agent, for example
	// "agent:finance" with prefix "agent:". Empty disables detection, so
	// every call is treated as north-south and this guard is a no-op.
	AgentToolPrefix string
	// Zones maps an agent id to its zone id. An agent with no entry is in
	// the empty zone "", which can only reach what an explicit edge allows.
	Zones map[string]string
	// AllowedEdges lists permitted directions as [callerZone, calleeZone].
	// The direction matters: [a, b] permits a to call into b, not the
	// reverse.
	AllowedEdges [][2]string
	// AllowIntraZone permits agents in the same non-empty zone to call each
	// other without needing an explicit edge.
	AllowIntraZone bool
}

// Result is the guard's decision plus the resolved zones, for audit.
type Result struct {
	Verdict     Verdict
	Reason      string
	CallerAgent string
	CalleeAgent string
	CallerZone  string
	CalleeZone  string
	// EastWest is true when the call was an agent-to-agent call and was
	// actually evaluated. False means the call was ordinary tool traffic
	// and the Allow is a pass-through, not a decision.
	EastWest bool
}

// Guard evaluates east-west calls against the configured zones and edges.
// Safe for concurrent use.
type Guard struct {
	cfg   Config
	mu    sync.RWMutex
	edges map[string]bool
}

const sep = "\x00"

// New returns a Guard for the given config.
func New(cfg Config) *Guard {
	edges := make(map[string]bool, len(cfg.AllowedEdges))
	for _, e := range cfg.AllowedEdges {
		edges[e[0]+sep+e[1]] = true
	}
	return &Guard{cfg: cfg, edges: edges}
}

// CalleeAgent returns the target agent id when tool is an agent-to-agent call,
// and false otherwise.
func (g *Guard) CalleeAgent(tool string) (string, bool) {
	p := g.cfg.AgentToolPrefix
	if p == "" || !strings.HasPrefix(tool, p) {
		return "", false
	}
	callee := strings.TrimSpace(strings.TrimPrefix(tool, p))
	if callee == "" {
		return "", false
	}
	return callee, true
}

func (g *Guard) zone(agent string) string {
	if z, ok := g.cfg.Zones[agent]; ok {
		return z
	}
	return ""
}

// ZoneOf returns the configured zone for an agent from the directory, or ""
// when the agent has no entry. Exported for read-only surfaces (the flow-map
// policy overlay) that need to place an agent without a live token.
func (g *Guard) ZoneOf(agent string) string {
	return g.zone(agent)
}

// Snapshot returns a deep copy of the guard's configuration, for read-only
// surfaces that render the current segmentation (the recommender builds a
// proposed config on top of the existing zones). Mutating the result does not
// affect the guard.
func (g *Guard) Snapshot() Config {
	out := Config{
		AgentToolPrefix: g.cfg.AgentToolPrefix,
		AllowIntraZone:  g.cfg.AllowIntraZone,
	}
	if g.cfg.Zones != nil {
		out.Zones = make(map[string]string, len(g.cfg.Zones))
		for k, v := range g.cfg.Zones {
			out.Zones[k] = v
		}
	}
	if g.cfg.AllowedEdges != nil {
		out.AllowedEdges = make([][2]string, len(g.cfg.AllowedEdges))
		copy(out.AllowedEdges, g.cfg.AllowedEdges)
	}
	return out
}

// Check decides whether callerAgent may call the given tool. If the tool is
// not an agent-to-agent call, the result is Allow with EastWest=false, so the
// caller can treat it as a pass-through.
//
// callerZone is the caller's zone as carried on its (signed) capability token.
// When non-empty it is authoritative and cannot be forged, so it wins over the
// config directory. When empty, the guard falls back to the configured Zones
// map keyed by agent id. The callee's zone always comes from the Zones
// directory: on this call the gateway sees only the callee's name, not its
// token.
func (g *Guard) Check(callerAgent, callerZone, tool string) Result {
	callee, ok := g.CalleeAgent(tool)
	if !ok {
		return Result{Verdict: VerdictAllow, EastWest: false, CallerAgent: callerAgent}
	}
	cz := callerZone
	if cz == "" {
		cz = g.zone(callerAgent)
	}
	tz := g.zone(callee)
	res := Result{
		CallerAgent: callerAgent, CalleeAgent: callee,
		CallerZone: cz, CalleeZone: tz, EastWest: true,
	}

	// Same-zone shortcut, when permitted.
	if g.cfg.AllowIntraZone && cz != "" && cz == tz {
		res.Verdict = VerdictAllow
		res.Reason = fmt.Sprintf("intra-zone call within %q", cz)
		return res
	}

	// Explicit directed edge from caller zone to callee zone.
	g.mu.RLock()
	allowed := g.edges[cz+sep+tz]
	g.mu.RUnlock()
	if allowed {
		res.Verdict = VerdictAllow
		res.Reason = fmt.Sprintf("east-west path %s -> %s permitted", zoneLabel(cz), zoneLabel(tz))
		return res
	}

	// Default-deny.
	res.Verdict = VerdictDeny
	res.Reason = fmt.Sprintf("no east-west path from zone %s to zone %s (default-deny)", zoneLabel(cz), zoneLabel(tz))
	return res
}

func zoneLabel(z string) string {
	if z == "" {
		return "(none)"
	}
	return z
}
