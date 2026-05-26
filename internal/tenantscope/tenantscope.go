// Package tenantscope enforces tenant isolation on tool calls whose
// arguments carry a tenant filter — most commonly vector-store and
// retrieval-augmented-generation (RAG) tools, but extensible to any
// tool whose backend supports multi-tenancy via a filter field.
//
// Threat closed (OWASP LLM08 — Vector & Embedding Weaknesses):
// an agent running under tenant A's capability token submits a
// vector-search request whose tenant filter is missing, blank, or
// wildcard ("*", null). The vector store happily returns matches
// from every tenant, including B's confidential embeddings. The
// agent now has cross-tenant data in its context — the same
// disclosure pattern as LLM02, but originating one layer further
// back in the retrieval stack.
//
// IntentGate already scopes ACCESS to the vector tool via the
// capability token's allowed-tools list, but that doesn't help when
// every tenant legitimately uses the same vector-search tool: the
// tool name is allowed; the filter scope is the lever that matters.
//
// This package wires a request-side check that, for tools the
// operator marks as tenant-scoped, enforces three rules:
//
//  1. The tenant filter argument MUST be present on the call (or the
//     gateway will inject it from the verified capability token).
//  2. The tenant filter value MUST equal the capability token's
//     tenant claim. Mismatches are blocked.
//  3. The tenant filter value MUST NOT be a wildcard, blank, or
//     "all" — even when the token's own tenant is empty (superadmin
//     case), a tool call still has to declare an explicit scope.
//
// Configuration:
//
//   - INTENTGATE_TENANT_SCOPED_TOOLS — CSV of tool names that
//     require enforcement. Empty disables the check (no-op).
//   - INTENTGATE_TENANT_SCOPE_ARG_PATH — default JSON-pointer-style
//     path to the tenant field on the call's Arguments map. E.g.
//     "tenant_id", "filter.tenant_id", "metadata_filter.tenant_id".
//     Per-tool overrides set in code (or in a future map env var).
//   - INTENTGATE_TENANT_SCOPE_INJECT — when "true", a missing tenant
//     filter is auto-injected from the capability token. When
//     "false" (default), missing filter is a violation.
//
// Like the PII filter, this package never persists the matched
// values into the audit chain. Audit rows record which tool and what
// kind of violation (missing | mismatch | wildcard).
package tenantscope

import (
	"errors"
	"fmt"
	"strings"
)

// Action mirrors the PII / output-schema action vocabulary.
type Action string

const (
	// ActionBlock is the safe default — refuse a call that violates
	// the tenant scope.
	ActionBlock Action = "block"
	// ActionInject auto-fills a missing tenant filter from the
	// verified capability token. Mismatches still block. Useful when
	// agents can't be trusted to include the filter themselves but
	// the capability token already pins the tenant.
	ActionInject Action = "inject"
	// ActionAllow logs violations but lets the call through. Telemetry
	// mode for a rollout.
	ActionAllow Action = "allow"
)

// ParseAction maps a string to an Action. Empty defaults to block.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ActionBlock, nil
	case "block":
		return ActionBlock, nil
	case "inject":
		return ActionInject, nil
	case "allow":
		return ActionAllow, nil
	default:
		return "", fmt.Errorf("tenantscope: unknown action %q (want block|inject|allow)", s)
	}
}

// ViolationKind is the bounded set of reasons a scope check can fail.
// Used in audit rows and the JSON-RPC error data payload — never the
// matched values themselves.
type ViolationKind string

const (
	KindMissing  ViolationKind = "missing"  // tenant filter absent
	KindWildcard ViolationKind = "wildcard" // filter is blank, "*", "all", or null
	KindMismatch ViolationKind = "mismatch" // filter does not equal token tenant
)

// Decision is the per-call outcome.
type Decision struct {
	Action    Action
	Violation ViolationKind // empty when no violation
	Reason    string        // human-readable; no secrets, no values
	// Mutated is true when the args map was rewritten (action=inject
	// path filled a missing filter). The handler knows to treat the
	// arguments as in-place modified.
	Mutated bool
	// Tool is the tool name the check ran against. Carried so the
	// handler can audit which scoped tool was checked.
	Tool string
}

// Allowed returns true when the call should proceed (clean or after
// successful injection).
func (d Decision) Allowed() bool {
	return d.Violation == "" || d.Action == ActionAllow ||
		(d.Action == ActionInject && d.Mutated && d.Violation == KindMissing)
}

// Enforcer is the runtime check. Build one at startup via
// [NewEnforcer]. Zero-value Enforcer is safe and no-ops on every call.
type Enforcer struct {
	// scoped is tool-name → arg path. Each scoped tool has a default
	// path; per-tool overrides take precedence. Path is a dot-
	// separated key sequence into the Arguments map: "tenant_id",
	// "filter.tenant_id", "metadata_filter.tenant_id".
	scoped map[string]string
	// defaultAction applies when a tool-specific override isn't set.
	defaultAction Action
	// perToolAction overrides defaultAction for specific tools.
	perToolAction map[string]Action
}

// NewEnforcer returns an Enforcer with no scoped tools (no-op). Call
// AddTool repeatedly to register scope-required tools.
func NewEnforcer(defaultAction Action) *Enforcer {
	if defaultAction == "" {
		defaultAction = ActionBlock
	}
	return &Enforcer{
		scoped:        map[string]string{},
		defaultAction: defaultAction,
		perToolAction: map[string]Action{},
	}
}

// AddTool registers a tool name + the dot-path to its tenant filter
// argument. Path "tenant" matches args["tenant"]; path
// "filter.tenant_id" matches args["filter"].(map[string]any)["tenant_id"].
func (e *Enforcer) AddTool(name, argPath string) {
	if e == nil {
		return
	}
	e.scoped[name] = argPath
}

// SetToolAction overrides the action for one tool. Pass "" to clear.
func (e *Enforcer) SetToolAction(name string, action Action) {
	if e == nil {
		return
	}
	if action == "" {
		delete(e.perToolAction, name)
		return
	}
	e.perToolAction[name] = action
}

// IsScoped reports whether the given tool needs scope enforcement.
func (e *Enforcer) IsScoped(tool string) bool {
	if e == nil {
		return false
	}
	_, ok := e.scoped[tool]
	return ok
}

// Tools returns the registered tool names (sorted for stable admin
// output).
func (e *Enforcer) Tools() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.scoped))
	for k := range e.scoped {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Check evaluates the call's arguments against the capability token's
// tenant claim. Returns a Decision describing what action to take and
// whether the args map was mutated in place.
//
// The args map may be modified when action=inject — caller treats it
// as in-place mutation. When action=block or action=allow, args is
// untouched.
func (e *Enforcer) Check(tool string, tokenTenant string, args map[string]any) Decision {
	if e == nil {
		return Decision{Tool: tool}
	}
	path, ok := e.scoped[tool]
	if !ok {
		return Decision{Tool: tool}
	}

	action, has := e.perToolAction[tool]
	if !has {
		action = e.defaultAction
	}
	d := Decision{Action: action, Tool: tool}

	value, present := readPath(args, path)
	switch {
	case !present:
		d.Violation = KindMissing
		d.Reason = fmt.Sprintf("tenant filter %q is required on tool %q but absent", path, tool)
		if action == ActionInject {
			if tokenTenant == "" {
				// Cannot inject from an empty token tenant — escalate
				// to block. Otherwise we'd silently let a superadmin's
				// missing filter call leak data.
				d.Action = ActionBlock
				d.Reason = fmt.Sprintf("tenant filter %q absent and capability token has no tenant claim to inject", path)
				return d
			}
			if err := writePath(args, path, tokenTenant); err != nil {
				d.Action = ActionBlock
				d.Reason = "tenant filter inject failed: " + err.Error()
				return d
			}
			d.Mutated = true
			d.Violation = "" // injection cleaned it
		}
		return d

	case isWildcardValue(value):
		d.Violation = KindWildcard
		d.Reason = fmt.Sprintf("tenant filter %q has a wildcard value on tool %q", path, tool)
		return d

	default:
		s, ok := value.(string)
		if !ok {
			d.Violation = KindMismatch
			d.Reason = fmt.Sprintf("tenant filter %q on tool %q is not a string (got %T)", path, tool, value)
			return d
		}
		if tokenTenant == "" {
			// Token claims no tenant. We do NOT silently accept
			// whatever the caller declared — that would let a
			// superadmin token leak across tenants by passing the
			// target tenant in the args. Caller must mint a
			// tenant-bound token.
			d.Violation = KindMismatch
			d.Reason = fmt.Sprintf("capability token has no tenant claim; cannot validate scope %q", s)
			return d
		}
		if s != tokenTenant {
			d.Violation = KindMismatch
			d.Reason = fmt.Sprintf("tenant filter %q on tool %q does not match capability token tenant", path, tool)
			return d
		}
	}
	// Match → no violation.
	return d
}

// LoadFromCSV is a convenience for parsing the INTENTGATE_TENANT_SCOPED_TOOLS
// env var. Format: "tool_name[:arg_path],tool_name[:arg_path],..."
// where arg_path defaults to "tenant_id" when omitted.
func (e *Enforcer) LoadFromCSV(csv string) error {
	if e == nil {
		return errors.New("tenantscope: LoadFromCSV on nil enforcer")
	}
	for _, raw := range strings.Split(csv, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		name, path, hasPath := strings.Cut(raw, ":")
		name = strings.TrimSpace(name)
		path = strings.TrimSpace(path)
		if name == "" {
			return fmt.Errorf("tenantscope: empty tool name in entry %q", raw)
		}
		if !hasPath || path == "" {
			path = "tenant_id"
		}
		e.scoped[name] = path
	}
	return nil
}

// readPath returns the value at the dot-separated key path in a JSON
// object, plus a present flag.
func readPath(m map[string]any, path string) (any, bool) {
	segs := strings.Split(path, ".")
	var cur any = m
	for _, s := range segs {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		v, present := obj[s]
		if !present {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

// writePath sets a value at the dot-separated key path, creating
// intermediate objects when necessary.
func writePath(m map[string]any, path string, value string) error {
	if m == nil {
		return errors.New("tenantscope: writePath on nil map")
	}
	segs := strings.Split(path, ".")
	cur := m
	for i, s := range segs {
		if i == len(segs)-1 {
			cur[s] = value
			return nil
		}
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	return nil
}

// isWildcardValue treats a small set of values as "all tenants" —
// the case the LLM08 check is specifically designed to refuse.
func isWildcardValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		t := strings.ToLower(strings.TrimSpace(x))
		return t == "" || t == "*" || t == "all" || t == "any"
	case bool:
		// A boolean tenant filter is meaningless — treat as wildcard
		// rather than mismatch so the audit row is honest.
		return true
	}
	return false
}
