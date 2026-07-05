// Package policy embeds the Open Policy Agent Rego engine inside the
// gateway and runs every tool call through it as the third of the four
// authorization checks (capability → intent → policy → budget).
//
// Why embedded? Two reasons. First, performance: a sidecar OPA would add
// an HTTP round-trip per tool call. Second, ops simplicity: one binary,
// one process, one container. The cost is binary size — OPA pulls in a
// lot of dependencies. For larger deployments where many gateways need
// to share centrally distributed policy bundles, swapping the embedded
// engine for an OPA sidecar is a single-file change behind this
// package's [Engine] interface.
//
// # Policy authoring
//
// Policies are written in Rego, OPA's declarative policy language. The
// gateway expects the policy to define a top-level rule named
// `decision` that returns an object with two or three fields:
//
//	{
//	  "allow":    true | false,
//	  "reason":   "human-readable explanation",
//	  "escalate": true | false  // optional, default false
//	}
//
// When `escalate` is true the gateway treats the call as
// human-approval-required: it pauses the request, enqueues it on the
// approvals queue, and resumes only when an operator approves
// (allowing the call to continue) or rejects (returning a block to
// the agent). `allow` should be set to false when `escalate` is true
// — the gateway treats them as mutually exclusive (escalate wins on
// the rare case both are set).
//
// The package and rule path are fixed at:
//
//	package intentgate.policy
//	decision := {...}
//
// See default_policy.rego for a starter policy that demonstrates a
// realistic mix of allow rules, deny rules, and a numeric threshold.
package policy

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

// QueryPath is the Rego query the engine evaluates for every request.
// Customer-provided policies must populate this rule.
const QueryPath = "data.intentgate.policy.decision"

//go:embed default_policy.rego
var defaultPolicy string

// DefaultPolicy returns the Rego source the gateway uses when no policy
// file is supplied via INTENTGATE_POLICY_FILE.
func DefaultPolicy() string {
	return defaultPolicy
}

// Decision is the verdict returned by the policy engine.
//
// Three legal shapes:
//
//   - Allow=true, Escalate=false  → call proceeds to budget check.
//   - Allow=false, Escalate=false → call blocked at policy stage.
//   - Allow=false, Escalate=true  → call paused for human approval;
//     eventual outcome decided by an
//     operator at /v1/admin/approvals.
//
// RequiresStepUp is an orthogonal advisory flag. When set, the
// audit event is annotated so a downstream UI (the Pro console,
// a SIEM dashboard) can surface "this call requires a fresh
// step-up factor" — even on an allow. Whether to actually GATE
// the call on step-up presence is encoded by the same Rego policy
// via Decision.Allow against input.capability.step_up_at, so the
// flag's purpose is observability rather than enforcement. A
// policy that wants strict enforcement returns both Allow=false
// AND RequiresStepUp=true; a policy that wants soft observation
// returns Allow=true AND RequiresStepUp=true.
type Decision struct {
	Allow          bool
	Escalate       bool
	Reason         string
	RequiresStepUp bool
	// PIIFilter is the optional per-request PII output-filter config
	// (LLM02). Populated from the Rego rule's `pii_filter` field when
	// the policy author wants to override the gateway's static PII
	// configuration for this specific call (e.g. allowing PII through
	// for an account-holder reading their own data). When nil, the
	// handler uses whatever static filter was configured at startup.
	// When non-nil, the handler builds a one-shot filter from this
	// config for this request only.
	//
	// See internal/pii and memos/llm02-pii-filter-design.md.
	PIIFilter *PIIFilterSpec
}

// PIIFilterSpec is the Rego-supplied PII filter configuration for one
// request. Fields mirror pii.Config so the handler can convert
// directly without coupling the policy package to the pii package.
//
// Example Rego:
//
//	decision := {
//	    "allow": true,
//	    "pii_filter": {
//	        "enabled": true,
//	        "patterns": ["email", "iban", "bsn"],
//	        "default_action": "redact",
//	        "per_pattern_action": {"iban": "block"},
//	    },
//	}
type PIIFilterSpec struct {
	Enabled          bool
	Patterns         []string
	DefaultAction    string
	PerPatternAction map[string]string
	CustomPatterns   []PIIFilterCustomPattern
}

// PIIFilterCustomPattern is one customer-declared additional pattern
// passed through from Rego. The handler validates the regex (ReDoS
// guard) when constructing the runtime filter.
type PIIFilterCustomPattern struct {
	Class string
	Regex string
}

// Engine wraps a prepared Rego query. Construct one at startup with
// [NewEngine] and call [Evaluate] for each request — preparation is
// expensive (Rego compilation) and Evaluate is fast.
type Engine struct {
	query rego.PreparedEvalQuery
}

// NewEngine compiles the supplied Rego source and returns an Engine
// ready to evaluate requests.
//
// If source is empty, the embedded default policy is used. The
// returned error wraps any compilation problem reported by OPA.
func NewEngine(ctx context.Context, source string) (*Engine, error) {
	if source == "" {
		source = defaultPolicy
	}
	r := rego.New(
		rego.Query(QueryPath),
		rego.Module("intentgate_policy.rego", source),
	)
	q, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: prepare for eval: %w", err)
	}
	return &Engine{query: q}, nil
}

// Evaluate runs the policy against input and returns the Decision.
//
// Failure modes — any of these return a non-nil error and the caller
// MUST fail closed (treat as deny) when error is non-nil:
//
//   - Rego runtime error.
//   - Query returns no result (no rule matched and there's no default).
//   - Result is not the expected map[string]any shape.
//   - Result missing the "allow" or "reason" fields.
func (e *Engine) Evaluate(ctx context.Context, input any) (Decision, error) {
	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return Decision{}, fmt.Errorf("policy: eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{}, errors.New("policy: no decision returned (missing default rule?)")
	}
	value := rs[0].Expressions[0].Value
	obj, ok := value.(map[string]any)
	if !ok {
		return Decision{}, fmt.Errorf("policy: decision is %T, want map[string]any", value)
	}
	allow, ok := obj["allow"].(bool)
	if !ok {
		return Decision{}, errors.New(`policy: decision missing "allow" boolean`)
	}
	reason, _ := obj["reason"].(string)   // reason is optional; empty is fine
	escalate, _ := obj["escalate"].(bool) // escalate is optional; default false
	// requires_step_up is optional; default false. Rego writes:
	//   decision := {"allow": ..., "reason": ..., "requires_step_up": true}
	// to signal that a fresh out-of-band factor SHOULD/MUST gate this
	// call. The audit event picks it up either way; the Rego rule
	// chooses whether to also flip Allow to false.
	requiresStepUp, _ := obj["requires_step_up"].(bool)

	// pii_filter is optional; absent means "use the gateway's static
	// PII config (or none)." When present, the handler will build a
	// per-request filter from this spec.
	var piiSpec *PIIFilterSpec
	if pf, ok := obj["pii_filter"].(map[string]any); ok {
		piiSpec = parsePIIFilterSpec(pf)
	}

	return Decision{
		Allow:          allow,
		Escalate:       escalate,
		Reason:         reason,
		RequiresStepUp: requiresStepUp,
		PIIFilter:      piiSpec,
	}, nil
}

// parsePIIFilterSpec converts a Rego-supplied map into a PIIFilterSpec.
// Missing or wrong-typed fields are tolerated (zero values used) — the
// policy author may legitimately omit fields and let the gateway's
// defaults apply, and the handler validates the final spec when
// building the runtime filter.
func parsePIIFilterSpec(m map[string]any) *PIIFilterSpec {
	spec := &PIIFilterSpec{}
	if v, ok := m["enabled"].(bool); ok {
		spec.Enabled = v
	}
	if v, ok := m["default_action"].(string); ok {
		spec.DefaultAction = v
	}
	if v, ok := m["patterns"].([]any); ok {
		for _, p := range v {
			if s, ok := p.(string); ok {
				spec.Patterns = append(spec.Patterns, s)
			}
		}
	}
	if v, ok := m["per_pattern_action"].(map[string]any); ok {
		spec.PerPatternAction = make(map[string]string, len(v))
		for k, av := range v {
			if s, ok := av.(string); ok {
				spec.PerPatternAction[k] = s
			}
		}
	}
	if v, ok := m["custom_patterns"].([]any); ok {
		for _, p := range v {
			cp, ok := p.(map[string]any)
			if !ok {
				continue
			}
			class, _ := cp["class"].(string)
			regex, _ := cp["regex"].(string)
			if class != "" && regex != "" {
				spec.CustomPatterns = append(spec.CustomPatterns, PIIFilterCustomPattern{
					Class: class,
					Regex: regex,
				})
			}
		}
	}
	return spec
}

// Input is a convenience builder for the request shape policies see.
//
// The shape mirrors the order of the four-check pipeline: a tool name,
// the args the agent supplied, the agent identifier from the verified
// capability token, and (when present) the structured intent from the
// extractor. Customer policies can ignore fields they don't care about.
type Input struct {
	Tool       string         `json:"tool"`
	Args       map[string]any `json:"args,omitempty"`
	AgentID    string         `json:"agent_id,omitempty"`
	SessionID  string         `json:"session_id,omitempty"`
	Intent     *InputIntent   `json:"intent,omitempty"`
	Capability *InputCap      `json:"capability,omitempty"`
	// EastWest is set only when the call is an agent-to-agent (east-west)
	// call. Policies read input.east_west to condition a specific edge on
	// the caller, the callee, and their zones (for example: deny any call
	// into the finance zone unless the caller is in procurement). Nil on
	// ordinary agent-to-tool calls.
	EastWest *InputEastWest `json:"east_west,omitempty"`
}

// InputEastWest is the agent-to-agent shape of a call, exposed to policy.
// Populated by the MCP handler from the east-west guard's resolution of the
// call, so caller and callee zones are the same values the default-deny zone
// gate used. Rego example:
//
//	deny if {
//	    input.east_west.callee_zone == "finance"
//	    input.east_west.caller_zone != "procurement"
//	}
type InputEastWest struct {
	CallerAgent string `json:"caller_agent,omitempty"`
	CallerZone  string `json:"caller_zone,omitempty"`
	CalleeAgent string `json:"callee_agent,omitempty"`
	CalleeZone  string `json:"callee_zone,omitempty"`
}

// InputIntent is the intent fields the policy can read.
type InputIntent struct {
	Summary        string   `json:"summary,omitempty"`
	AllowedTools   []string `json:"allowed_tools,omitempty"`
	ForbiddenTools []string `json:"forbidden_tools,omitempty"`
	Confidence     float64  `json:"confidence,omitempty"`
}

// InputCap exposes a small slice of the verified capability token.
//
// Tenant is set by the MCP handler from the verified capability
// token (see [capability.Token.Tenant]). The [Reloader] reads it to
// dispatch the evaluation to the right per-tenant compiled engine
// — customer Rego that doesn't care about multi-tenancy can ignore
// the field, and tenants without their own promoted policy fall
// back to the default fallback module installed at startup or by
// a superadmin promote.
type InputCap struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	// Zone is the east-west segmentation zone from the signed capability
	// token (see [capability.Token.Zone]). Policies can read
	// input.capability.zone to gate north-south tool access by zone
	// alongside the per-zone scope guard. Empty when the token carries no
	// zone (pre-v4 tokens are not accepted, so in practice this is the
	// caller's zone, defaulting to "default").
	Zone string `json:"zone,omitempty"`
	// StepUpAt is the unix-seconds timestamp of the most recent
	// out-of-band step-up authentication (TOTP / WebAuthn / hardware
	// key) on this capability token's chain. Sourced from the
	// signed [capability.CaveatStepUp] caveat the mint endpoint
	// stamped when the operator confirmed a fresh factor; agents
	// cannot fabricate or alter it.
	//
	// Zero when the token has no step-up caveat. Rego policies that
	// gate high-risk operations write:
	//
	//   now := time.now_ns() / 1000000000
	//   fresh := now - input.capability.step_up_at < 300
	//   decision := { "allow": fresh, "reason": "...", "requires_step_up": true }
	//
	// What "fresh enough" means is operator policy — the gateway
	// doesn't impose a window.
	StepUpAt int64 `json:"step_up_at,omitempty"`
}
