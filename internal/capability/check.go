package capability

import (
	"errors"
	"fmt"
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
		if !contains(c.Tools, ctx.Tool) {
			return fmt.Errorf("tool %q not in allowed set", ctx.Tool)
		}
		return nil

	case CaveatToolBlacklist:
		if ctx.EastWest {
			return nil
		}
		if contains(c.Tools, ctx.Tool) {
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
