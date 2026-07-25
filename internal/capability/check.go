package capability

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

// RequestContext is the per-call data the caveat evaluator needs.
//
// AgentID is taken from the verified token's Subject — never from the
// untrusted request body — and is what CaveatAgentLock compares against.
// Tool is the MCP method's tool name. Now is injectable for tests; if
// zero, time.Now() is used.
//
// EastWest marks the call as an agent-to-agent (east-west) call. On such a
// call the tool is an agent target, not a north-south tool, so the tool
// whitelist/blacklist caveats do not apply — east-west authorization is the
// gateway zone policy plus the callee-allow caveat. Every other caveat
// (expiry, agent-lock, not-before, max-calls, step-up) is still enforced.
type RequestContext struct {
	AgentID  string
	Tool     string
	Now      time.Time
	EastWest bool
	// Risk is the caller's live runtime risk score (0–100) supplied by the
	// handler for [CaveatRiskMax] evaluation. Zero means "no score available"
	// and never trips a risk ceiling — the gate fails open on a missing score
	// by design, because a risk_max caveat is a containment ceiling, not the
	// primary control. Populate it from the agent's current risk signal.
	Risk int
}

// Check evaluates a token's caveats against ctx in order.
//
// Check returns the first caveat error encountered, or nil if all
// pass. Unknown caveat types are denied: if a token carries a caveat
// this gateway version doesn't understand, it is not safe to allow
// the call — we cannot tell whether the request satisfies a constraint
// we can't even parse.
//
// Check assumes Verify has already succeeded. Callers MUST run Verify
// before Check; otherwise an attacker could craft a token whose
// caveats trivially pass.
func (t *Token) Check(ctx RequestContext) error {
	now := ctx.Now
	if now.IsZero() {
		now = time.Now()
	}

	if t.NotBefore != 0 && now.Unix() < t.NotBefore {
		return errors.New("token not yet valid (nbf in future)")
	}

	for i, c := range t.Caveats {
		if err := evalCaveat(c, ctx, now); err != nil {
			return fmt.Errorf("caveat %d (%s): %w", i, c.Type, err)
		}
	}
	return nil
}

func evalCaveat(c Caveat, ctx RequestContext, now time.Time) error {
	switch c.Type {
	case CaveatExpiry:
		if c.Expiry == 0 {
			return errors.New("expiry caveat missing exp value")
		}
		if now.Unix() >= c.Expiry {
			return errors.New("expired")
		}
		return nil

	case CaveatAgentLock:
		if c.Agent == "" {
			return errors.New("agent_lock caveat missing agent value")
		}
		if c.Agent != ctx.AgentID {
			return fmt.Errorf("token bound to %q, request from %q", c.Agent, ctx.AgentID)
		}
		return nil

	case CaveatToolWhitelist:
		// North-south tool scope does not gate an east-west (agent-to-agent)
		// call: the callee agent is authorized by the gateway zone policy and
		// the callee-allow caveat, so skip the tool whitelist for such calls.
		if ctx.EastWest {
			return nil
		}
		if !matchAnyTool(c.Tools, ctx.Tool) {
			return fmt.Errorf("tool %q not in allowed set", ctx.Tool)
		}
		return nil

	case CaveatToolBlacklist:
		if ctx.EastWest {
			return nil
		}
		if matchAnyTool(c.Tools, ctx.Tool) {
			return fmt.Errorf("tool %q is forbidden", ctx.Tool)
		}
		return nil

	case CaveatMaxCalls:
		// Informational at this layer. The budget package consults
		// the persistent counter store and enforces the limit as the
		// fourth pipeline check. We accept the caveat as valid here
		// so that signed tokens carrying max_calls aren't rejected
		// by the capability stage.
		return nil

	case CaveatStepUp:
		// Informational at this layer. Rego policies enforce recency
		// against input.capability.step_up_at — the mcp handler
		// surfaces the timestamp from this caveat into the policy
		// input. We accept the caveat as valid here so that signed
		// tokens carrying step_up aren't rejected by the capability
		// stage. A missing step_up_at value means "no step-up
		// recorded" — Rego treats it as 0 and any "must be recent"
		// rule fires.
		if c.StepUpAt < 0 {
			return errors.New("step_up caveat has negative step_up_at value")
		}
		return nil

	case CaveatMcpAllow:
		// North-south server scope. Like tool_allow it does not gate an
		// east-west (agent-to-agent) call — the callee is authorized by the
		// zone policy and callee-allow, not by MCP server membership.
		if ctx.EastWest {
			return nil
		}
		if !matchAnyServer(c.Servers, ctx.Tool) {
			return fmt.Errorf("tool %q not on an allowed MCP server", ctx.Tool)
		}
		return nil

	case CaveatRateLimit:
		// Informational at this layer: the per-minute call cap is enforced by
		// the velocity stage against the persistent counter (same split as
		// max_calls). Accept as valid so a signed rate cap isn't rejected here.
		if c.RatePerMin < 0 {
			return errors.New("rate_limit caveat has negative rate_per_min value")
		}
		return nil

	case CaveatMaxCost:
		// Informational at this layer: the per-minute spend cap is enforced by
		// the velocity stage against the persistent spend counter.
		if c.MaxCents < 0 {
			return errors.New("max_cost caveat has negative max_cents value")
		}
		return nil

	case CaveatRiskMax:
		// Enforced inline — needs no persistent state, only the live score the
		// handler supplies via ctx.Risk. Ceiling 0 disables the gate; a zero
		// ctx.Risk (no score available) never trips it, so the gate fails open
		// on a missing score by design.
		if c.RiskMax < 0 {
			return errors.New("risk_max caveat has negative risk_max value")
		}
		if c.RiskMax > 0 && ctx.Risk > c.RiskMax {
			return fmt.Errorf("caller risk %d exceeds token ceiling %d", ctx.Risk, c.RiskMax)
		}
		return nil

	case CaveatCalleeAllow:
		// Informational at this layer. The callee agent is not part of a
		// north-south RequestContext, so this caveat is enforced in the
		// east-west stage via Token.CanCall. We accept it as valid here so
		// that signed tokens carrying an agent-to-agent allowlist aren't
		// rejected by the capability stage.
		return nil

	default:
		return fmt.Errorf("unknown caveat type %q (deny by default)", c.Type)
	}
}

// CanCall reports whether this token's agent-to-agent caveats permit calling
// the given callee agent (in calleeZone), and a reason when they do not.
//
// East-west authorization has two independent gates: the gateway's zone policy
// (internal/eastwest) and this per-token allowlist. Both must permit the call.
//
// A token with no [CaveatCalleeAllow] is unrestricted here: the gateway zone
// policy alone governs east-west. When one or more callee_allow caveats are
// present, the callee must satisfy EVERY one of them, so attenuation only
// narrows which agents a delegated child may call, never widens them. Within a
// single caveat, the callee is permitted if its agent id is listed in Callees
// OR its zone is listed in CalleeZones. A callee_allow caveat with both lists
// empty permits nothing (fail closed).
//
// CanCall assumes Verify has already succeeded, exactly like Check.
func (t *Token) CanCall(calleeAgent, calleeZone string) (bool, string) {
	for _, c := range t.Caveats {
		if c.Type != CaveatCalleeAllow {
			continue
		}
		if contains(c.Callees, calleeAgent) || contains(c.CalleeZones, calleeZone) {
			continue
		}
		return false, fmt.Sprintf("token does not permit calling agent %q (zone %q)", calleeAgent, calleeZone)
	}
	return true, ""
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// matchAnyTool reports whether tool matches any of the patterns. A pattern
// may use shell-style globs ("read_*", "list_*"); a pattern with no glob
// metacharacters is compared for exact equality, so this stays backward
// compatible with existing exact-string tool_allow / tool_deny caveats. It
// only affects caveat evaluation, never the signed token bytes, so it does
// not change any existing token's signature. This lets the Pro console
// express per-agent tool scope (allowed_tool_schemas) as globs.
func matchAnyTool(patterns []string, tool string) bool {
	for _, p := range patterns {
		if p == tool {
			return true
		}
		if strings.ContainsAny(p, "*?[") {
			if ok, err := path.Match(p, tool); err == nil && ok {
				return true
			}
		}
	}
	return false
}

// matchAnyServer reports whether tool belongs to any of the allowed MCP
// servers. A tool belongs to server S when it equals S or is prefixed "S.",
// "S:" or "S/" — so "sap" matches "sap.invoice.pay" but not "saphana.read".
// This is how the console's allowed_mcp_servers attribute is enforced once
// baked into a mcp_allow caveat, without the gateway reading the Pro DB.
func matchAnyServer(servers []string, tool string) bool {
	for _, s := range servers {
		if s == "" {
			continue
		}
		if tool == s ||
			strings.HasPrefix(tool, s+".") ||
			strings.HasPrefix(tool, s+":") ||
			strings.HasPrefix(tool, s+"/") {
			return true
		}
	}
	return false
}
