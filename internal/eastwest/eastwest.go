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
// Decision: per agent pair, plus default-deny. The unit of control is one
// named caller calling one named callee. A rule may name the two agents
// directly (AllowedPairs), which is the primary form, and either side may be a
// trailing-* pattern so a fleet can be written without listing every member.
//
// Labels (the Zones map and AllowedEdges) are an authoring convenience layered
// on top: at 500 agents there are 250,000 ordered pairs and nobody can write
// them by hand, so a label lets one rule stand for many pairs. A label is never
// a statement about reachability. Two agents carrying the same label have no
// path between them unless a rule grants it, which is why AllowIntraZone is
// deprecated: it is the one setting that granted reachability by membership.
//
// This is the containment control: a compromised agent cannot recruit another
// agent unless someone wrote a rule naming that exact pair, directly or through
// a pattern.
//
// Deterministic and config-driven. A call that is NOT an agent-to-agent call
// is a no-op here and passes straight through, so wiring this in front of the
// pipeline never affects ordinary tool traffic.
package eastwest

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Verdict is the east-west decision.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
)

// Config configures east-west authorization. The zero value is inert: with no
// AgentToolPrefix, nothing is treated as an agent-to-agent call.
// Rule is one authorised agent-to-agent call, with the governance record that
// justifies it.
//
// # Why this is not a pair of strings
//
// It was [2]string until an operator asked the question the console could not
// answer: "why may procurement call finance, who agreed to it, and is that
// still true?" A pair carries the decision and discards the reasoning, which
// makes the ruleset a firewall config. The point of authorising an agent is
// that somebody accepted a risk on a date for a stated purpose, and that this
// lapses. That is a record, not an edge.
//
// Every field except From and To is optional. A rule with no metadata behaves
// exactly as the old pair did, so configs written before this type keep
// working and keep enforcing.
type Rule struct {
	// From and To are the caller and callee. Either may be an exact agent id,
	// a prefix pattern ("agent-procure-*"), or "*" for any agent. Direction
	// matters: this permits From to call To, never the reverse.
	From string `json:"from" yaml:"from"`
	To   string `json:"to" yaml:"to"`

	// Purpose is why this call is permitted, in the operator's words
	// ("procurement confirms invoice totals before raising a PO"). Carried
	// into the audit record so an investigator reads intent, not just a
	// verdict.
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	// Owner is the person or team accountable for this permission continuing
	// to exist. Not the person who typed it: the person who answers for it.
	Owner string `json:"owner,omitempty" yaml:"owner,omitempty"`
	// ApprovedBy and ApprovedAt record the acceptance of the risk.
	ApprovedBy string    `json:"approved_by,omitempty" yaml:"approved_by,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitempty" yaml:"approved_at,omitempty"`
	// ExpiresAt ends the permission. Zero means it does not expire.
	//
	// This is ENFORCED, not displayed: past this instant the rule stops
	// matching and the call is denied by default. An expiry that the gateway
	// ignored would be worse than none, because the console would show a
	// governance control that does nothing.
	ExpiresAt time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	// ReviewBy is the date this permission should next be re-justified. Unlike
	// ExpiresAt it does not stop the call: it moves the rule into the "needs
	// review" state so the console can raise it. Governance nags; it does not
	// break production without warning.
	ReviewBy time.Time `json:"review_by,omitempty" yaml:"review_by,omitempty"`
}

// Expired reports whether the rule has passed its expiry at the given instant.
func (r Rule) Expired(now time.Time) bool {
	return !r.ExpiresAt.IsZero() && now.After(r.ExpiresAt)
}

// NeedsReview reports whether the rule is due re-justification. A rule that
// was never approved by anyone needs review from the moment it exists: an
// unapproved permission is the thing an audit asks about first.
func (r Rule) NeedsReview(now time.Time) bool {
	if r.ApprovedBy == "" {
		return true
	}
	return !r.ReviewBy.IsZero() && now.After(r.ReviewBy)
}

type Config struct {
	// AgentToolPrefix marks a tool call as an agent-to-agent call. A tool
	// named "<prefix><agent-id>" targets another agent, for example
	// "agent:finance" with prefix "agent:". Empty disables detection, so
	// every call is treated as north-south and this guard is a no-op.
	AgentToolPrefix string
	// AllowedPairs lists permitted calls as [callerAgent, calleeAgent]. This
	// is the primary rule form: the decision is about these two agents and
	// nothing else. Either side may be an exact agent id, or a pattern with a
	// trailing "*" ("agent-procure-*"), or "*" for any agent. Direction
	// matters: [a, b] lets a call b, never the reverse.
	//
	// Nothing is implied. Listing agents under the same label does not put a
	// pair here; only a rule does.
	AllowedPairs [][2]string
	// Rules is the same permission carried as a record. Evaluated together
	// with AllowedPairs: a call is permitted if either names it. Both forms
	// exist so an estate can adopt the record form rule by rule instead of in
	// one migration, and so a config written by hand stays writable by hand.
	Rules []Rule
	// Zones maps an agent id to a label. Labels exist so one rule can stand
	// for many agent pairs when authoring at scale. Membership grants nothing
	// on its own.
	Zones map[string]string
	// AllowedEdges lists permitted directions between labels as
	// [callerLabel, calleeLabel]. Each entry expands to the pairs of agents
	// carrying those labels. Direction matters.
	AllowedEdges [][2]string
	// AllowIntraZone permits agents sharing a label to call each other with no
	// rule naming them.
	//
	// ObserveOnly reports what the ruleset would decide without enforcing it:
	// a call that has no rule is allowed through, and the result carries
	// WouldDeny so the audit records it as "this would have been blocked".
	//
	// This exists to solve a real ordering problem. The recommender derives
	// rules from allowed traffic, so an estate that starts correctly (deny by
	// default, no rules) produces no allowed traffic, and therefore no
	// recommendation: there is no safe way in. Observe mode gives an operator a
	// window where nothing breaks, every path the agents genuinely need is
	// recorded, and the ruleset can then be adopted and enforced in one click.
	//
	// It is not a safe resting state. Anything is reachable while it is on, so
	// the gateway warns at startup and the console surfaces it prominently.
	ObserveOnly bool
	// Deprecated: this grants reachability by group membership, which is the
	// property this package exists to remove. Write the pairs you want, using
	// a pattern if the fleet is large. Retained so existing configs keep
	// loading; it is evaluated last and reported as such.
	AllowIntraZone bool
}

// Result is the guard's decision plus the resolved zones, for audit.
type Result struct {
	// CalleeUnzoned is true when the callee is not in the Zones directory at
	// all. Such a call is denied, but the cause is a configuration gap (an
	// agent nobody mapped to a zone), not a policy decision. Callers surface
	// it distinctly so an operator is not left reading "default-deny" while
	// the real problem is a missing directory entry.
	CalleeUnzoned bool
	// WouldDeny is true when observe mode let a call through that the rules
	// would otherwise have refused. The verdict is Allow, so the call is not
	// blocked, but this is the signal that the estate is not yet enforcing.
	WouldDeny bool
	// DecidedBy names which kind of rule produced the verdict, so an audit
	// record can distinguish "someone authorised these two agents" from
	// "these two agents happen to share a label". Empty for pass-through.
	// One of: "agent-rule", "label-rule", "shared-label", "default-deny".
	DecidedBy   string
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

// Guard evaluates east-west calls against the configured rules.
// Safe for concurrent use, and safe to update while serving traffic.
type Guard struct {
	mu sync.RWMutex
	// st is swapped wholesale on update. Readers take a pointer under the
	// read lock and then work on it without holding anything, so a rule
	// change never blocks in-flight authorization and a single call can
	// never see half of an old ruleset and half of a new one.
	st *state
}

// state is one immutable compiled ruleset.
type state struct {
	cfg   Config
	edges map[string]bool
	// Exact agent pairs, for an O(1) hit on the common case.
	pairs map[string]pairRule
	// Pairs where at least one side is a pattern. Kept as a slice because it
	// has to be scanned; in practice it is short (one entry per fleet rule).
	globs []pairRule
}

type pairRule struct {
	from, to string
	// rule is the governance record this came from, zero for a bare pair.
	rule Rule
}

const sep = "\x00"

// matches reports whether pattern accepts agent. A pattern is either an exact
// id, or a prefix ending in "*". "*" alone accepts any agent.
func matches(pattern, agent string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(agent, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == agent
}

func isPattern(s string) bool { return strings.HasSuffix(s, "*") }

// compile turns a config into a ruleset ready to evaluate.
func compile(cfg Config) *state {
	edges := make(map[string]bool, len(cfg.AllowedEdges))
	for _, e := range cfg.AllowedEdges {
		edges[e[0]+sep+e[1]] = true
	}
	// Both rule forms compile into one index. A bare pair becomes a Rule with
	// no metadata, so evaluation has a single path and there is no way for the
	// two forms to diverge in what they permit.
	all := make([]Rule, 0, len(cfg.AllowedPairs)+len(cfg.Rules))
	for _, p := range cfg.AllowedPairs {
		all = append(all, Rule{From: p[0], To: p[1]})
	}
	all = append(all, cfg.Rules...)

	pairs := make(map[string]pairRule, len(all))
	var globs []pairRule
	for _, r := range all {
		pr := pairRule{from: r.From, to: r.To, rule: r}
		if isPattern(r.From) || isPattern(r.To) {
			globs = append(globs, pr)
			continue
		}
		pairs[r.From+sep+r.To] = pr
	}
	return &state{cfg: cfg, edges: edges, pairs: pairs, globs: globs}
}

// New returns a Guard for the given config.
func New(cfg Config) *Guard {
	return &Guard{st: compile(cfg)}
}

// Replace swaps in a new ruleset atomically, with no restart and no dropped
// calls. This is what lets an operator change who may call whom from the
// console: the alternative, editing a file and restarting the enforcement
// point, is not something a security team can be asked to do for a routine
// permission change, and it leaves no record of who changed what.
func (g *Guard) Replace(cfg Config) {
	st := compile(cfg)
	g.mu.Lock()
	g.st = st
	g.mu.Unlock()
}

// snap returns the current ruleset.
func (g *Guard) snap() *state {
	g.mu.RLock()
	st := g.st
	g.mu.RUnlock()
	return st
}

// pairAllowed reports whether a rule names this exact caller and callee,
// either literally or through a pattern, and returns the rule that matched.
func (st *state) pairAllowed(caller, callee string) (pairRule, bool) {
	// An expired rule does not match. Enforced here rather than filtered at
	// compile time so expiry takes effect on the wall clock, not on whenever
	// the config was last reloaded: a permission that lapses at midnight must
	// stop working at midnight, on a gateway nobody has touched for a month.
	now := time.Now()
	if pr, ok := st.pairs[caller+sep+callee]; ok && !pr.rule.Expired(now) {
		return pr, true
	}
	for _, r := range st.globs {
		if matches(r.from, caller) && matches(r.to, callee) && !r.rule.Expired(now) {
			return r, true
		}
	}
	return pairRule{}, false
}

// CalleeAgent returns the target agent id when tool is an agent-to-agent call,
// and false otherwise.
func (g *Guard) CalleeAgent(tool string) (string, bool) { return g.snap().calleeAgent(tool) }

func (st *state) calleeAgent(tool string) (string, bool) {
	p := st.cfg.AgentToolPrefix
	if p == "" || !strings.HasPrefix(tool, p) {
		return "", false
	}
	callee := strings.TrimSpace(strings.TrimPrefix(tool, p))
	if callee == "" {
		return "", false
	}
	return callee, true
}

func (st *state) zone(agent string) string {
	if z, ok := st.cfg.Zones[agent]; ok {
		return z
	}
	return ""
}

// ZoneOf returns the configured zone for an agent from the directory, or ""
// when the agent has no entry. Exported for read-only surfaces (the flow-map
// policy overlay) that need to place an agent without a live token.
func (g *Guard) ZoneOf(agent string) string {
	return g.snap().zone(agent)
}

// Snapshot returns a deep copy of the guard's configuration, for read-only
// surfaces that render the current segmentation (the recommender builds a
// proposed config on top of the existing zones). Mutating the result does not
// affect the guard.
func (g *Guard) Snapshot() Config {
	st := g.snap()
	out := Config{
		AgentToolPrefix: st.cfg.AgentToolPrefix,
		AllowIntraZone:  st.cfg.AllowIntraZone,
		// ObserveOnly has to survive the snapshot or every read-back reports
		// the estate as enforcing. A console that shows a verdict while the
		// gateway is only observing is telling the operator their agents are
		// contained when nothing is being stopped.
		ObserveOnly: st.cfg.ObserveOnly,
	}
	if st.cfg.Zones != nil {
		out.Zones = make(map[string]string, len(st.cfg.Zones))
		for k, v := range st.cfg.Zones {
			out.Zones[k] = v
		}
	}
	if st.cfg.AllowedEdges != nil {
		out.AllowedEdges = make([][2]string, len(st.cfg.AllowedEdges))
		copy(out.AllowedEdges, st.cfg.AllowedEdges)
	}
	if st.cfg.AllowedPairs != nil {
		out.AllowedPairs = make([][2]string, len(st.cfg.AllowedPairs))
		copy(out.AllowedPairs, st.cfg.AllowedPairs)
	}
	// Rules carry the governance record: purpose, owner, approval, expiry. A
	// snapshot that omitted them would hand the console a config it could save
	// straight back, erasing every justification in the estate and leaving the
	// bare pair behind. The rule would still authorize, so nothing would look
	// broken; the audit trail would simply be gone.
	if st.cfg.Rules != nil {
		out.Rules = make([]Rule, len(st.cfg.Rules))
		copy(out.Rules, st.cfg.Rules)
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
	// One snapshot for the whole decision: a rule change mid-call must not
	// let this call be judged against two different rulesets.
	st := g.snap()
	callee, ok := st.calleeAgent(tool)
	if !ok {
		return Result{Verdict: VerdictAllow, EastWest: false, CallerAgent: callerAgent}
	}
	cz := callerZone
	if cz == "" {
		cz = st.zone(callerAgent)
	}
	tz := st.zone(callee)
	res := Result{
		CallerAgent: callerAgent, CalleeAgent: callee,
		CallerZone: cz, CalleeZone: tz, EastWest: true,
	}

	// A rule naming these two agents wins over anything label-derived. This is
	// the control the product is about, so it is decided first and reported as
	// its own kind: the audit trail can then show that a human authorised this
	// specific caller to reach this specific callee.
	if rule, ok := st.pairAllowed(callerAgent, callee); ok {
		res.Verdict = VerdictAllow
		res.DecidedBy = "agent-rule"
		if rule.from == callerAgent && rule.to == callee {
			res.Reason = fmt.Sprintf("rule permits %s -> %s", callerAgent, callee)
		} else {
			res.Reason = fmt.Sprintf("rule %s -> %s permits %s -> %s", rule.from, rule.to, callerAgent, callee)
		}
		return res
	}

	// Label rule: one entry standing for many pairs. Same decision, written at
	// a coarser grain.
	if st.edges[cz+sep+tz] {
		res.Verdict = VerdictAllow
		res.DecidedBy = "label-rule"
		res.Reason = fmt.Sprintf("rule permits %s -> %s, which covers %s -> %s",
			zoneLabel(cz), zoneLabel(tz), callerAgent, callee)
		return res
	}

	// Shared label. Evaluated last and named plainly, because no rule was
	// written for this pair: they reach each other only by belonging to the
	// same group.
	if st.cfg.AllowIntraZone && cz != "" && cz == tz {
		res.Verdict = VerdictAllow
		res.DecidedBy = "shared-label"
		res.Reason = fmt.Sprintf(
			"%s and %s both carry label %q and intra-label calls are enabled; no rule names this pair",
			callerAgent, callee, cz)
		return res
	}

	// Default-deny. Distinguish "no path between two known zones" (a policy
	// decision) from "the callee is in no zone at all" (a config gap), because
	// the second is almost always a mistake and is otherwise invisible.
	// Observe mode: report the decision, do not impose it.
	if st.cfg.ObserveOnly {
		res.Verdict = VerdictAllow
		res.WouldDeny = true
		res.DecidedBy = "observe-only"
		res.Reason = fmt.Sprintf(
			"observe mode: no rule permits %s -> %s, so this would be blocked once enforcement is on",
			callerAgent, callee)
		return res
	}

	res.Verdict = VerdictDeny
	res.DecidedBy = "default-deny"
	if tz == "" {
		res.CalleeUnzoned = true
		res.Reason = fmt.Sprintf(
			"no rule permits %s -> %s, and %s carries no label either, so no label rule can cover it (add a rule for this pair, or label the agent)",
			callerAgent, callee, callee)
		return res
	}
	res.Reason = fmt.Sprintf("no rule permits %s -> %s (default-deny)", callerAgent, callee)
	return res
}

func zoneLabel(z string) string {
	if z == "" {
		return "(none)"
	}
	return z
}
