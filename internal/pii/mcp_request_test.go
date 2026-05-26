package pii

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplyToMCPRequest_AllowWhenNoPII(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	args := map[string]any{
		"query":   "today's invoices",
		"limit":   10,
		"sort_by": "due_date",
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionAllow {
		t.Errorf("expected Allow, got %s", dec.Action)
	}
	if args["query"] != "today's invoices" {
		t.Errorf("Allow should not mutate args")
	}
}

func TestApplyToMCPRequest_RedactsEmailInQuery(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	args := map[string]any{
		"query": "site:linkedin.com joe@intentgate.app",
		"limit": 5,
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", dec.Action)
	}
	got := args["query"].(string)
	if strings.Contains(got, "joe@intentgate.app") {
		t.Errorf("email leaked through redaction: %s", got)
	}
	if !strings.Contains(got, "[REDACTED:email]") {
		t.Errorf("expected [REDACTED:email] marker, got: %s", got)
	}
	if dec.Counts[ClassEmail] < 1 {
		t.Errorf("expected at least 1 email count, got %d", dec.Counts[ClassEmail])
	}
}

func TestApplyToMCPRequest_BlocksOnIBANOverride(t *testing.T) {
	f, _ := NewFilter(Config{
		Enabled:       true,
		DefaultAction: ActionRedact,
		PerPatternAction: map[Class]Action{
			ClassIBAN: ActionBlock,
		},
	})
	args := map[string]any{
		"to_account": "NL91 ABNA 0417 1643 00",
		"amount_eur": 99.50,
		"memo":       "monthly invoice",
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionBlock {
		t.Errorf("expected Block due to IBAN override, got %s", dec.Action)
	}
	if dec.Counts[ClassIBAN] != 1 {
		t.Errorf("expected 1 IBAN count, got %d", dec.Counts[ClassIBAN])
	}
	// Block must NOT mutate — the caller may want to log the original
	// args before discarding the request.
	if args["to_account"] != "NL91 ABNA 0417 1643 00" {
		t.Error("Block should not mutate args")
	}
}

func TestApplyToMCPRequest_NestedRedaction(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	args := map[string]any{
		"customer": map[string]any{
			"id":    "CUST-42",
			"email": "ap@initech.example",
			"phone": "+31 6 12345678",
		},
		"options": map[string]any{
			"sort_by": "name",
			"limit":   25,
		},
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", dec.Action)
	}
	customer := args["customer"].(map[string]any)
	if customer["email"] == "ap@initech.example" {
		t.Error("nested email not redacted")
	}
	if !strings.Contains(customer["email"].(string), "[REDACTED:email]") {
		t.Errorf("nested email missing redaction marker: %s", customer["email"])
	}
	if customer["id"] != "CUST-42" {
		t.Error("Redact mutated a non-PII field (CUST-42 should be untouched)")
	}
	if options, ok := args["options"].(map[string]any); !ok || options["sort_by"] != "name" {
		t.Error("Redact mutated unrelated nested field")
	}
}

func TestApplyToMCPRequest_SliceRedaction(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	args := map[string]any{
		"recipients": []any{
			"alice@example.com",
			"bob@example.com",
			"plain text no pii",
		},
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", dec.Action)
	}
	recipients := args["recipients"].([]any)
	for i, r := range recipients[:2] {
		s := r.(string)
		if strings.Contains(s, "@example.com") {
			t.Errorf("recipient %d not redacted: %s", i, s)
		}
		if !strings.Contains(s, "[REDACTED:email]") {
			t.Errorf("recipient %d missing marker: %s", i, s)
		}
	}
	// The third item had no PII; should stay intact.
	if recipients[2] != "plain text no pii" {
		t.Errorf("non-PII slice element was mutated: %v", recipients[2])
	}
}

func TestApplyToMCPRequest_NonStringScalarsIgnored(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	// A 16-digit numeric value shaped like a credit card. Our filter
	// only inspects strings, so this should NOT be flagged. (Agents
	// passing PII as numbers are a known footgun the filter doesn't
	// try to catch — that's documented in the design memo.)
	args := map[string]any{
		"ref":    4111111111111111, // numeric, not a string
		"active": true,
		"empty":  nil,
	}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionAllow {
		t.Errorf("non-string scalars should not match: got %s", dec.Action)
	}
}

func TestApplyToMCPRequest_NilSafe(t *testing.T) {
	var f *Filter
	args := map[string]any{"q": "anything"}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionAllow {
		t.Errorf("nil filter should Allow, got %s", dec.Action)
	}
}

func TestApplyToMCPRequest_DisabledPassesThrough(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: false})
	args := map[string]any{"q": "leak ap@initech.example freely"}
	dec := f.ApplyToMCPRequest(args)
	if dec.Action != ActionAllow {
		t.Errorf("disabled filter should Allow, got %s", dec.Action)
	}
	if args["q"] != "leak ap@initech.example freely" {
		t.Error("disabled filter should not mutate args")
	}
}

func TestApplyToMCPRequest_EmptyArgs(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	dec := f.ApplyToMCPRequest(map[string]any{})
	if dec.Action != ActionAllow {
		t.Errorf("empty args should Allow, got %s", dec.Action)
	}
}

func TestApplyToMCPRequestBytes_RoundTripsRedacted(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	input := json.RawMessage(`{"customer":{"email":"ap@initech.example","id":"CUST-1"},"limit":10}`)
	out, dec := f.ApplyToMCPRequestBytes(input)
	if dec.Action != ActionRedact {
		t.Fatalf("expected Redact, got %s", dec.Action)
	}
	if strings.Contains(string(out), "ap@initech.example") {
		t.Errorf("email leaked through bytes round-trip: %s", out)
	}
	if !strings.Contains(string(out), "[REDACTED:email]") {
		t.Errorf("missing redaction marker: %s", out)
	}
	// Re-parsing the output should still yield a structurally valid
	// MCP arguments object.
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("redacted output is not valid JSON: %v", err)
	}
	customer, ok := parsed["customer"].(map[string]any)
	if !ok {
		t.Fatal("redaction stripped the customer object")
	}
	if customer["id"] != "CUST-1" {
		t.Error("redaction modified a non-PII field")
	}
}

func TestApplyToMCPRequestBytes_NonObjectPassesThrough(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	// MCP arguments should be an object, but if a non-object slips
	// through (a JSON array, scalar) we pass through rather than
	// crash. Same defensive behaviour as the response-side filter.
	cases := []json.RawMessage{
		json.RawMessage(`["foo@bar.com"]`),
		json.RawMessage(`"ap@initech.example"`),
		json.RawMessage(`42`),
		json.RawMessage(`null`),
	}
	for _, in := range cases {
		out, dec := f.ApplyToMCPRequestBytes(in)
		if dec.Action != ActionAllow {
			t.Errorf("non-object input %s: expected Allow, got %s", in, dec.Action)
		}
		if string(out) != string(in) {
			t.Errorf("non-object input %s was mutated to %s", in, out)
		}
	}
}

func TestApplyToMCPRequestBytes_NonJSON(t *testing.T) {
	f, _ := NewFilter(Config{Enabled: true, DefaultAction: ActionRedact})
	garbage := json.RawMessage(`not valid json {][`)
	out, dec := f.ApplyToMCPRequestBytes(garbage)
	if dec.Action != ActionAllow {
		t.Errorf("non-JSON input: expected Allow, got %s", dec.Action)
	}
	if string(out) != string(garbage) {
		t.Error("non-JSON input was mutated")
	}
}
