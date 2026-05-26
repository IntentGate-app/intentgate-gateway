package pii

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Filter disabled / no-op behaviour
// ---------------------------------------------------------------------

func TestFilter_Disabled_NoOp(t *testing.T) {
	f, err := NewFilter(Config{Enabled: false})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	input := "leak joe@intentgate.app and 192.168.1.1 freely"
	d := f.ApplyToString(input)
	if d.Action != ActionAllow {
		t.Errorf("disabled filter should Allow, got %s", d.Action)
	}
	if d.Output != input {
		t.Errorf("disabled filter should not modify input, got %q", d.Output)
	}
	if len(d.Counts) != 0 {
		t.Errorf("disabled filter should report no counts, got %v", d.Counts)
	}
}

func TestFilter_Nil_Safe(t *testing.T) {
	var f *Filter
	d := f.ApplyToString("anything goes")
	if d.Action != ActionAllow {
		t.Errorf("nil filter should Allow, got %s", d.Action)
	}
}

// ---------------------------------------------------------------------
// Redact action
// ---------------------------------------------------------------------

func TestFilter_Redact_DefaultAction(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      []Class{ClassEmail},
		DefaultAction: ActionRedact,
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	input := "Reach out to joe@intentgate.app for help."
	d := f.ApplyToString(input)
	if d.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", d.Action)
	}
	if !strings.Contains(d.Output, "[REDACTED:email]") {
		t.Errorf("expected redaction marker, got %q", d.Output)
	}
	if strings.Contains(d.Output, "@intentgate.app") {
		t.Errorf("email leaked through redaction: %q", d.Output)
	}
	if d.Counts[ClassEmail] != 1 {
		t.Errorf("expected 1 email count, got %d", d.Counts[ClassEmail])
	}
}

func TestFilter_Redact_DefaultWhenUnset(t *testing.T) {
	// DefaultAction unset → should default to Redact
	f, err := NewFilter(Config{
		Enabled:  true,
		Patterns: []Class{ClassEmail},
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	d := f.ApplyToString("user@example.com")
	if d.Action != ActionRedact {
		t.Errorf("unset default should be Redact, got %s", d.Action)
	}
}

// ---------------------------------------------------------------------
// Block action
// ---------------------------------------------------------------------

func TestFilter_Block(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      []Class{ClassIBAN},
		DefaultAction: ActionBlock,
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	d := f.ApplyToString("send to NL91 ABNA 0417 1643 00")
	if d.Action != ActionBlock {
		t.Errorf("expected Block, got %s", d.Action)
	}
	if d.Output != "" {
		t.Errorf("Block should produce empty output, got %q", d.Output)
	}
	if d.Counts[ClassIBAN] != 1 {
		t.Errorf("expected 1 IBAN count in Block decision, got %d", d.Counts[ClassIBAN])
	}
}

// ---------------------------------------------------------------------
// Per-pattern override (most-restrictive wins)
// ---------------------------------------------------------------------

func TestFilter_PerPatternOverride_BlockBeatsRedact(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      []Class{ClassEmail, ClassIBAN},
		DefaultAction: ActionRedact,
		PerPatternAction: map[Class]Action{
			ClassIBAN: ActionBlock, // IBANs are too sensitive to redact-and-forward
		},
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}

	// Input with both an email (would Redact) and an IBAN (must Block)
	input := "Email: joe@intentgate.app. IBAN: NL91 ABNA 0417 1643 00"
	d := f.ApplyToString(input)
	if d.Action != ActionBlock {
		t.Errorf("Block should beat Redact via per-pattern override, got %s", d.Action)
	}
	if d.Output != "" {
		t.Errorf("Block should produce empty output, got %q", d.Output)
	}
	if d.Counts[ClassEmail] != 1 || d.Counts[ClassIBAN] != 1 {
		t.Errorf("expected both classes counted, got %v", d.Counts)
	}
}

func TestFilter_PerPatternOverride_OnlyAffectedClassEscalates(t *testing.T) {
	// Email is Allow; IBAN is Block. Input has only email → should Allow (no block).
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      []Class{ClassEmail, ClassIBAN},
		DefaultAction: ActionAllow,
		PerPatternAction: map[Class]Action{
			ClassIBAN: ActionBlock,
		},
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	d := f.ApplyToString("just an email here: user@example.com")
	// Per-pattern overrides only apply when the matching class hits.
	// Email matched but Email has no override → use DefaultAction (Allow).
	// IBAN has Block override but didn't match → not relevant.
	if d.Action != ActionAllow {
		t.Errorf("expected Allow (no IBAN to block), got %s", d.Action)
	}
}

// ---------------------------------------------------------------------
// Custom patterns
// ---------------------------------------------------------------------

func TestFilter_CustomPattern(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:  true,
		Patterns: []Class{}, // no built-ins
		CustomPatterns: []CustomPattern{
			{Class: "acme_id", Regex: `ACME-\d{4}-\d{4}`},
		},
		DefaultAction: ActionRedact,
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	d := f.ApplyToString("customer ACME-1234-5678 has an issue")
	if d.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", d.Action)
	}
	if !strings.Contains(d.Output, "[REDACTED:acme_id]") {
		t.Errorf("expected acme_id redaction, got %q", d.Output)
	}
	if d.Counts["acme_id"] != 1 {
		t.Errorf("expected 1 acme_id count, got %d", d.Counts["acme_id"])
	}
}

func TestFilter_RejectsBadCustomPattern(t *testing.T) {
	_, err := NewFilter(Config{
		Enabled: true,
		CustomPatterns: []CustomPattern{
			{Class: "ReDoS", Regex: `(a+)+`}, // nested quantifier — must be rejected
		},
	})
	if err == nil {
		t.Error("expected NewFilter to reject ReDoS-prone custom pattern")
	}
}

func TestFilter_RejectsEmptyClassLabel(t *testing.T) {
	_, err := NewFilter(Config{
		Enabled: true,
		CustomPatterns: []CustomPattern{
			{Class: "", Regex: `\d+`},
		},
	})
	if err == nil {
		t.Error("expected NewFilter to reject empty class label")
	}
}

// ---------------------------------------------------------------------
// No matches
// ---------------------------------------------------------------------

func TestFilter_NoMatches_Allow(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      []Class{ClassEmail},
		DefaultAction: ActionRedact,
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	input := "perfectly innocuous text, no PII anywhere"
	d := f.ApplyToString(input)
	if d.Action != ActionAllow {
		t.Errorf("no matches should Allow, got %s", d.Action)
	}
	if d.Output != input {
		t.Errorf("Allow should not modify input, got %q", d.Output)
	}
}

// ---------------------------------------------------------------------
// Realistic combined scenario
// ---------------------------------------------------------------------

func TestFilter_RealisticAgentResponse_RedactThenForward(t *testing.T) {
	f, err := NewFilter(Config{
		Enabled:       true,
		Patterns:      nil, // all built-ins
		DefaultAction: ActionRedact,
	})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	input := `Account holder: joe@intentgate.app
Phone on file: +31 6 12345678
Last login IP: 192.168.1.42`
	d := f.ApplyToString(input)
	if d.Action != ActionRedact {
		t.Errorf("expected Redact, got %s", d.Action)
	}
	// Verify nothing identifiable leaks through
	leaks := []string{"@intentgate.app", "+31 6", "192.168.1.42"}
	for _, leak := range leaks {
		if strings.Contains(d.Output, leak) {
			t.Errorf("leak in redacted output: %q remained", leak)
		}
	}
	t.Logf("Filter counts: %v · classes: %v", d.Counts, d.MatchedClasses)
}
