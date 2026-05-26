package pii

import (
	"encoding/json"
	"strings"
	"testing"
)

// Helper: build an MCP tools/call result blob for testing.
func mcpResult(texts ...string) json.RawMessage {
	content := make([]map[string]any, 0, len(texts))
	for _, t := range texts {
		content = append(content, map[string]any{"type": "text", "text": t})
	}
	result := map[string]any{
		"content": content,
		"isError": false,
	}
	blob, _ := json.Marshal(result)
	return blob
}

func TestApplyToMCPResult_AllowWhenNoMatches(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	in := mcpResult("Your account is in good standing.")
	out, dec := f.ApplyToMCPResult(in)
	if dec.Action != ActionAllow {
		t.Errorf("expected Allow, got %s", dec.Action)
	}
	if string(out) != string(in) {
		t.Errorf("Allow should not mutate result")
	}
}

func TestApplyToMCPResult_RedactsTextBlocks(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	in := mcpResult("Email: joe@intentgate.app", "Phone: +31 6 12345678")
	out, dec := f.ApplyToMCPResult(in)
	if dec.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", dec.Action)
	}

	// Verify the output blob has redaction markers and no original PII.
	if strings.Contains(string(out), "joe@intentgate.app") {
		t.Errorf("email leaked through redaction: %s", string(out))
	}
	if !strings.Contains(string(out), "[REDACTED:email]") {
		t.Errorf("expected [REDACTED:email] marker in output: %s", string(out))
	}
	if dec.Counts[ClassEmail] < 1 {
		t.Errorf("expected at least 1 email count, got %d", dec.Counts[ClassEmail])
	}

	// Verify the result is still valid MCP shape.
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("redacted result is not valid JSON: %v", err)
	}
	if _, ok := parsed["content"]; !ok {
		t.Error("redacted result missing 'content' field")
	}
}

func TestApplyToMCPResult_BlocksOnSensitiveClass(t *testing.T) {
	f, _ := NewFilter(Config{
		Enabled:       true,
		DefaultAction: ActionRedact,
		PerPatternAction: map[Class]Action{
			ClassIBAN: ActionBlock,
		},
	})
	in := mcpResult("Your IBAN: NL91 ABNA 0417 1643 00")
	_, dec := f.ApplyToMCPResult(in)
	if dec.Action != ActionBlock {
		t.Errorf("expected Block due to IBAN override, got %s", dec.Action)
	}
	if dec.Counts[ClassIBAN] != 1 {
		t.Errorf("expected 1 IBAN count, got %d", dec.Counts[ClassIBAN])
	}
}

func TestApplyToMCPResult_FilterDisabled_PassesThrough(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: false})
	in := mcpResult("leak joe@intentgate.app freely")
	out, dec := f.ApplyToMCPResult(in)
	if dec.Action != ActionAllow {
		t.Errorf("disabled filter should Allow, got %s", dec.Action)
	}
	if string(out) != string(in) {
		t.Errorf("disabled filter should not mutate result")
	}
}

func TestApplyToMCPResult_NilSafe(t *testing.T) {
	var f *Filter
	in := mcpResult("anything")
	out, dec := f.ApplyToMCPResult(in)
	if dec.Action != ActionAllow {
		t.Errorf("nil filter should Allow, got %s", dec.Action)
	}
	if string(out) != string(in) {
		t.Error("nil filter should not mutate result")
	}
}

func TestApplyToMCPResult_PreservesUnknownFields(t *testing.T) {
	// Upstream MCP result with vendor-specific fields the gateway
	// shouldn't strip. Make sure redaction round-trip preserves them.
	original := map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": "Contact joe@intentgate.app"},
		},
		"isError":     false,
		"_intentgate": map[string]any{"decision": "allow"}, // vendor extension
		"_upstreamVendor": map[string]any{
			"version":   "1.2.3",
			"requestID": "abc-123",
		},
	}
	blob, _ := json.Marshal(original)

	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	out, dec := f.ApplyToMCPResult(blob)
	if dec.Action != ActionRedact {
		t.Fatalf("expected Redact, got %s", dec.Action)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("invalid JSON after redaction: %v", err)
	}
	if _, ok := parsed["_intentgate"]; !ok {
		t.Error("redaction stripped _intentgate vendor field")
	}
	if _, ok := parsed["_upstreamVendor"]; !ok {
		t.Error("redaction stripped _upstreamVendor field")
	}
}

func TestApplyToMCPResult_NonJSONResult(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	garbage := json.RawMessage(`this is not JSON {][[`)
	out, dec := f.ApplyToMCPResult(garbage)
	// Non-JSON: filter is a no-op (we can't scan structured text from junk).
	if dec.Action != ActionAllow {
		t.Errorf("non-JSON should pass through as Allow, got %s", dec.Action)
	}
	if string(out) != string(garbage) {
		t.Errorf("non-JSON should not be mutated")
	}
}

func TestApplyToMCPResult_NoContentField(t *testing.T) {
	// Some MCP tools may return a result without a content array
	// (initialize, ping, etc.). Filter should pass through.
	blob := json.RawMessage(`{"isError": false}`)
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	_, dec := f.ApplyToMCPResult(blob)
	if dec.Action != ActionAllow {
		t.Errorf("no content field should Allow, got %s", dec.Action)
	}
}
