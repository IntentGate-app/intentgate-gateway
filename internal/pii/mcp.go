package pii

import (
	"encoding/json"
)

// MCPDecision is the outcome of applying the filter to an MCP
// tools/call response's content blocks. It mirrors the per-string
// Decision struct but operates on the structured MCP result.
type MCPDecision struct {
	Action         Action
	Counts         map[Class]int
	MatchedClasses []Class
}

// ApplyToMCPResult walks an MCP tools/call result object, applies the
// filter to every text content block, and either:
//
//   - returns ActionAllow with the result unmodified (no PII matched);
//   - returns ActionRedact with the result mutated in-place so each
//     text block has its matched substrings replaced by [REDACTED:<class>]
//     markers (safe to forward to the agent);
//   - returns ActionBlock or ActionEscalate with the result unchanged
//     (caller must NOT forward; should return -32015 to the agent).
//
// The function operates on a json.RawMessage payload (the
// upstream-supplied result blob). On Allow it returns the input
// unchanged; on Redact it returns a re-encoded blob with the redacted
// text blocks substituted; on Block/Escalate it returns the input
// unchanged (since the caller will discard it).
//
// Counts are aggregated across every text block; per-block counts are
// not preserved because callers want one audit row per response, not
// one per block.
func (f *Filter) ApplyToMCPResult(result json.RawMessage) (json.RawMessage, MCPDecision) {
	if f == nil || !f.cfg.Enabled || len(result) == 0 {
		return result, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}

	// Unmarshal into a generic map so unknown fields (like _intentgate
	// metadata, isError, anything an upstream MCP server might add)
	// survive the round-trip. ToolCallResult's strict shape would lose
	// unknown fields.
	var obj map[string]any
	if err := json.Unmarshal(result, &obj); err != nil {
		// Non-JSON result body; nothing to scan. Pass through.
		return result, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}

	// Collect every text block's text into a single string so we get
	// one Decision per response (rather than per block). For Redact
	// action we then need to map redactions back to each block; we
	// do that by re-applying the detector per block, which keeps the
	// counts coherent because the detector is pure.
	contentAny, ok := obj["content"]
	if !ok {
		return result, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}
	contentList, ok := contentAny.([]any)
	if !ok {
		return result, MCPDecision{Action: ActionAllow, Counts: map[Class]int{}}
	}

	// First pass: aggregate all text and decide the action.
	var combined string
	for _, item := range contentList {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		btype, _ := block["type"].(string)
		if btype != "text" {
			continue
		}
		text, _ := block["text"].(string)
		if text != "" {
			if combined != "" {
				combined += "\n"
			}
			combined += text
		}
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
		// Block / Escalate: the caller will discard the result entirely
		// and return -32015 to the agent, so the body we return here
		// is irrelevant.
		return result, mcpDec
	case ActionRedact:
		// Walk each text block again, redact its text in place.
		for _, item := range contentList {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			btype, _ := block["type"].(string)
			if btype != "text" {
				continue
			}
			text, _ := block["text"].(string)
			if text == "" {
				continue
			}
			matches := f.detector.Detect(text)
			redacted, _ := Redact(text, matches)
			block["text"] = redacted
		}
		obj["content"] = contentList

		// Re-encode. If this ever fails (it shouldn't — we just
		// unmarshalled it), fall back to the original.
		encoded, err := json.Marshal(obj)
		if err != nil {
			return result, mcpDec
		}
		return encoded, mcpDec
	default:
		return result, mcpDec
	}
}
