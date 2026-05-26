package pii

import (
	"encoding/json"
)

// ApplyToMCPRequest is the bidirectional sibling of [ApplyToMCPResult].
// It walks the arguments object of an MCP tools/call REQUEST and either
// passes it through, blocks the call, or returns a mutated arguments
// object with matched PII redacted before the gateway forwards the call
// to the upstream tool server.
//
// The threat case it closes: an agent that already holds PII in its
// context (from a previous tool call, from memory, from the user
// prompt) includes that PII in arguments to a tool that should NOT
// receive it. Examples:
//
//   - Calling web_search with a customer's email or BSN in the query
//     string. The PII now leaves the customer's perimeter, going to a
//     third-party search provider that has no need-to-know.
//   - Calling a CRM tool with the customer's IBAN in a notes field
//     when the CRM doesn't store payment data.
//   - Calling a logging tool with a credit card in a debug message.
//
// Capability tokens and Rego policy already gate WHICH tools an agent
// can call. This filter scrubs the CONTENTS of allowed calls so
// outbound minimisation (GDPR Article 5(1)(c)) is enforced symmetrically
// with the response-side filter.
//
// Wire-level treatment of each action:
//
//   - ActionAllow:    arguments unchanged, request forwarded to upstream.
//   - ActionRedact:   matched substrings in argument values replaced with
//     [REDACTED:<class>] before forwarding. The agent
//     doesn't get a chance to recover the original — the
//     redacted argument is what reaches upstream.
//   - ActionBlock:    request never reaches upstream. Caller returns
//     -32015 (CodePIIBlocked — same code as response-side;
//     the audit row's direction field distinguishes).
//   - ActionEscalate: same wire treatment as Block today; reserved for
//     the Pro console-driven approval flow.
//
// The function takes a generic map[string]any (the arguments value from
// an MCP tools/call params) rather than a json.RawMessage so callers
// can mutate the arguments in place when the action is Redact. On Allow
// or Block the args are unchanged. The returned map is the SAME map
// the caller passed in — no defensive copy — because redaction is
// always destructive to the original (we don't want stale references
// pointing at unredacted values).
//
// Mutations:
//
//   - On Redact: every string value (at any depth in the arguments
//     tree) is scanned. Matched substrings are replaced with the same
//     [REDACTED:<class>] markers the response-side filter uses.
//   - Nested maps and slices are walked recursively. Non-string scalar
//     values (numbers, bools, null) are left alone — PII detection only
//     applies to text.
//
// Counts are aggregated across the entire argument tree (one MCPDecision
// per request, not per leaf string) so the audit row carries a single
// row per request just like the response side.
func (f *Filter) ApplyToMCPRequest(args map[string]any) MCPDecision {
	if f == nil || !f.cfg.Enabled || len(args) == 0 {
		return MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}

	// First pass: aggregate every string value into a single combined
	// string so we get one Decision (one action) for the whole request.
	// Same pattern as ApplyToMCPResult — the detector is pure and we
	// re-scan per-leaf during the mutation pass.
	var combined string
	collectStrings(args, func(s string) {
		if s == "" {
			return
		}
		if combined != "" {
			combined += "\n"
		}
		combined += s
	})

	if combined == "" {
		// Nothing scannable in the arguments. Could be a tool whose
		// arguments are entirely numeric / boolean. Pass through.
		return MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}

	decision := f.ApplyToString(combined)

	mcpDec := MCPDecision{
		Action:         decision.Action,
		Counts:         decision.Counts,
		MatchedClasses: decision.MatchedClasses,
	}

	switch decision.Action {
	case ActionAllow, ActionBlock, ActionEscalate:
		// Allow: nothing to mutate.
		// Block / Escalate: the caller will discard the request and
		// return -32015 to the agent, so the args we leave behind are
		// irrelevant (though we leave them untouched anyway — easier
		// to reason about).
		return mcpDec
	case ActionRedact:
		// Walk every string value in the args tree and apply the
		// per-string redaction. The detector is pure so re-applying
		// per-leaf yields the same per-class counts the aggregate
		// scan produced.
		redactStringsInPlace(args, f)
		return mcpDec
	default:
		return mcpDec
	}
}

// collectStrings walks v and invokes visit on every string value found.
// Recurses into maps and slices; ignores non-string scalars. This is
// the read-only first pass used to decide the overall action.
func collectStrings(v any, visit func(string)) {
	switch x := v.(type) {
	case string:
		visit(x)
	case map[string]any:
		for _, val := range x {
			collectStrings(val, visit)
		}
	case []any:
		for _, item := range x {
			collectStrings(item, visit)
		}
		// Other types (numbers, bools, json.Number, nil) — nothing to
		// scan. Numeric IDs that LOOK like PII (e.g. a credit-card-shaped
		// integer) won't be caught — but that's correct behaviour, since
		// the agent should be passing those as strings if they want
		// content-class inspection.
	}
}

// redactStringsInPlace walks v and replaces matched PII substrings in
// every string value with [REDACTED:<class>] markers. Mutates maps and
// slices in place. The detector is pure so this re-scan yields counts
// equivalent to the first pass's aggregate scan.
func redactStringsInPlace(v any, f *Filter) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				matches := f.detector.Detect(s)
				if len(matches) > 0 {
					redacted, _ := Redact(s, matches)
					x[k] = redacted
				}
			} else {
				redactStringsInPlace(val, f)
			}
		}
	case []any:
		for i, item := range x {
			if s, ok := item.(string); ok {
				matches := f.detector.Detect(s)
				if len(matches) > 0 {
					redacted, _ := Redact(s, matches)
					x[i] = redacted
				}
			} else {
				redactStringsInPlace(item, f)
			}
		}
	}
}

// ApplyToMCPRequestBytes is a convenience wrapper around ApplyToMCPRequest
// for callers that hold the request arguments as a JSON blob (e.g. the
// gateway handler, which receives params.Arguments as json.RawMessage).
// On Redact the returned bytes are the re-encoded arguments with PII
// substituted; on Allow / Block / Escalate the input is returned
// unchanged (the caller will discard it on Block / Escalate).
//
// Returns (originalOrRedactedJSON, decision). Non-JSON input is passed
// through with Allow — same defensive behaviour as ApplyToMCPResult on
// a malformed result body.
func (f *Filter) ApplyToMCPRequestBytes(args json.RawMessage) (json.RawMessage, MCPDecision) {
	if f == nil || !f.cfg.Enabled || len(args) == 0 {
		return args, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}
	var obj map[string]any
	if err := json.Unmarshal(args, &obj); err != nil {
		// Not a JSON object — could be a JSON array or scalar at top
		// level. MCP spec says arguments is an object; if it's not we
		// have nothing structured to scan. Pass through.
		return args, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}
	dec := f.ApplyToMCPRequest(obj)
	if dec.Action != ActionRedact {
		return args, dec
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		// Re-encode failure is essentially impossible (we just
		// unmarshalled), but fall back to the original blob.
		return args, dec
	}
	return encoded, dec
}
