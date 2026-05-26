package pii

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------
// Built-in pattern coverage tests
// ---------------------------------------------------------------------

func TestDetector_Email(t *testing.T) {
	d := NewDetector([]Class{ClassEmail})
	cases := []struct {
		in   string
		hits int
	}{
		{"contact us at joe@intentgate.app today", 1},
		{"two: a@x.com and b@y.org", 2},
		{"no emails here", 0},
		{"j.cordoba@intentgate.app", 1},
		{"this @is.not.an.email but x@y.com is", 1},
	}
	for _, c := range cases {
		got := d.Detect(c.in)
		if len(got) != c.hits {
			t.Errorf("input %q: expected %d email matches, got %d (%v)", c.in, c.hits, len(got), got)
		}
	}
}

func TestDetector_IBAN(t *testing.T) {
	d := NewDetector([]Class{ClassIBAN})
	cases := []struct {
		in    string
		valid bool
	}{
		// Real ABN AMRO test IBAN (passes mod-97)
		{"transfer to NL91 ABNA 0417 1643 00", true},
		// Same IBAN, no spaces
		{"NL91ABNA0417164300", true},
		// Random 18-digit garbage that matches regex but fails mod-97
		{"NL00ABNA0417164300", false},
		// Not an IBAN at all
		{"this is not banking info", false},
	}
	for _, c := range cases {
		got := d.Detect(c.in)
		if c.valid && len(got) == 0 {
			t.Errorf("input %q: expected valid IBAN match, got none", c.in)
		}
		if !c.valid && len(got) > 0 {
			t.Errorf("input %q: expected no match (invalid checksum), got %v", c.in, got)
		}
	}
}

func TestDetector_BSN(t *testing.T) {
	d := NewDetector([]Class{ClassBSN})
	cases := []struct {
		in    string
		valid bool
	}{
		// Dutch test BSN (passes mod-11): 111222333
		// Construct: 9*1+8*1+7*1+6*2+5*2+4*2+3*3+2*3+(-1)*3 = 9+8+7+12+10+8+9+6-3 = 66 = 0 mod 11
		{"BSN 111222333 belongs to nobody", true},
		// Real-looking but invalid checksum
		{"BSN 123456789 fake", false},
		// 8-digit historic BSN format is intentionally not supported
		// (would produce too many false positives on ordinary 8-digit
		// numbers). Modern BSN is always 9 digits.
		{"old 8-digit BSN 52689141 is not matched", false},
	}
	for _, c := range cases {
		got := d.Detect(c.in)
		if c.valid && len(got) == 0 {
			t.Errorf("input %q: expected valid BSN match, got none", c.in)
		}
		if !c.valid && len(got) > 0 {
			t.Errorf("input %q: expected no match (invalid checksum), got %v", c.in, got)
		}
	}
}

func TestDetector_CreditCard_Luhn(t *testing.T) {
	d := NewDetector([]Class{ClassCreditCard})
	cases := []struct {
		in    string
		valid bool
	}{
		// Visa test number (passes Luhn)
		{"card 4012 8888 8888 1881", true},
		// Same, no spaces
		{"4012888888881881", true},
		// Random 16 digits, fails Luhn
		{"1234567890123456", false},
	}
	for _, c := range cases {
		got := d.Detect(c.in)
		if c.valid && len(got) == 0 {
			t.Errorf("input %q: expected valid CC match, got none", c.in)
		}
		if !c.valid && len(got) > 0 {
			t.Errorf("input %q: expected no match (Luhn fail), got %v", c.in, got)
		}
	}
}

func TestDetector_Phone(t *testing.T) {
	d := NewDetector([]Class{ClassPhoneIntl})
	inputs := []string{
		"call +31 6 12345678 if you need help",
		"+1 (415) 555-0100 is a US line",
		"NL: +31611223344",
	}
	for _, in := range inputs {
		got := d.Detect(in)
		if len(got) == 0 {
			t.Errorf("input %q: expected phone match", in)
		}
	}
}

func TestDetector_IPv4(t *testing.T) {
	d := NewDetector([]Class{ClassIPv4})
	got := d.Detect("server at 192.168.1.42 went down; failover to 10.0.0.1")
	if len(got) != 2 {
		t.Errorf("expected 2 IPv4 matches, got %d (%v)", len(got), got)
	}
	// Out-of-range octets should NOT match
	got = d.Detect("not an IP: 999.999.999.999")
	if len(got) != 0 {
		t.Errorf("expected 0 matches for invalid IPv4, got %d", len(got))
	}
}

func TestDetector_VAT_EU(t *testing.T) {
	d := NewDetector([]Class{ClassVATEU})
	got := d.Detect("invoice for NL123456789B01")
	if len(got) == 0 {
		t.Error("expected Dutch VAT number match")
	}
}

// ---------------------------------------------------------------------
// Redaction tests
// ---------------------------------------------------------------------

func TestRedact_SingleClass(t *testing.T) {
	d := NewDetector([]Class{ClassEmail})
	input := "Contact joe@intentgate.app for details."
	matches := d.Detect(input)
	out, counts := Redact(input, matches)
	if !strings.Contains(out, "[REDACTED:email]") {
		t.Errorf("expected redaction marker in output, got %q", out)
	}
	if strings.Contains(out, "joe@intentgate.app") {
		t.Errorf("original email leaked through redaction: %q", out)
	}
	if counts[ClassEmail] != 1 {
		t.Errorf("expected 1 email count, got %d", counts[ClassEmail])
	}
}

func TestRedact_MultipleMatches(t *testing.T) {
	d := NewDetector([]Class{ClassEmail, ClassIPv4})
	input := "From 10.0.0.1: ping a@x.com, then 10.0.0.2: ping b@y.org"
	matches := d.Detect(input)
	out, counts := Redact(input, matches)
	if strings.Contains(out, "@") {
		t.Errorf("expected all emails redacted, got %q", out)
	}
	if strings.Contains(out, "10.0.0.") {
		t.Errorf("expected all IPs redacted, got %q", out)
	}
	if counts[ClassEmail] != 2 {
		t.Errorf("expected 2 email counts, got %d", counts[ClassEmail])
	}
	if counts[ClassIPv4] != 2 {
		t.Errorf("expected 2 IPv4 counts, got %d", counts[ClassIPv4])
	}
}

func TestRedact_PreservesNonPII(t *testing.T) {
	d := NewDetector([]Class{ClassEmail})
	input := "Hello! Your account is active. Contact joe@intentgate.app for help. Thanks."
	matches := d.Detect(input)
	out, _ := Redact(input, matches)
	if !strings.HasPrefix(out, "Hello! Your account is active.") {
		t.Errorf("redaction destroyed surrounding context: %q", out)
	}
	if !strings.HasSuffix(out, "for help. Thanks.") {
		t.Errorf("redaction destroyed surrounding context: %q", out)
	}
}

func TestRedact_EmptyMatches(t *testing.T) {
	input := "no PII here"
	out, counts := Redact(input, nil)
	if out != input {
		t.Errorf("expected unchanged input, got %q", out)
	}
	if len(counts) != 0 {
		t.Errorf("expected empty counts, got %v", counts)
	}
}

// ---------------------------------------------------------------------
// CountByClass test (for block-decision audit rows)
// ---------------------------------------------------------------------

func TestCountByClass(t *testing.T) {
	matches := []Match{
		{Class: ClassEmail, Value: "a@x.com"},
		{Class: ClassEmail, Value: "b@y.com"},
		{Class: ClassIBAN, Value: "NL91 ABNA 0417 1643 00"},
	}
	counts := CountByClass(matches)
	if counts[ClassEmail] != 2 {
		t.Errorf("expected 2 emails, got %d", counts[ClassEmail])
	}
	if counts[ClassIBAN] != 1 {
		t.Errorf("expected 1 IBAN, got %d", counts[ClassIBAN])
	}
}

// ---------------------------------------------------------------------
// Custom-pattern tests
// ---------------------------------------------------------------------

func TestAddCustomPattern_Valid(t *testing.T) {
	d := NewDetector([]Class{}) // no built-ins
	err := d.AddCustomPattern("acme_id", `ACME-\d{4}-\d{4}`)
	if err != nil {
		t.Fatalf("AddCustomPattern failed: %v", err)
	}
	got := d.Detect("customer ACME-1234-5678 has an issue")
	if len(got) != 1 || got[0].Class != "acme_id" {
		t.Errorf("expected acme_id match, got %v", got)
	}
}

func TestAddCustomPattern_RejectsNestedQuantifier(t *testing.T) {
	d := NewDetector(nil)
	err := d.AddCustomPattern("bad", `(a+)+`)
	if err == nil {
		t.Error("expected nested-quantifier pattern to be rejected")
	}
}

func TestAddCustomPattern_RejectsInvalidRegex(t *testing.T) {
	d := NewDetector(nil)
	err := d.AddCustomPattern("bad", `[unclosed`)
	if err == nil {
		t.Error("expected invalid regex to be rejected")
	}
}

// ---------------------------------------------------------------------
// Combined / realistic scenario
// ---------------------------------------------------------------------

func TestDetect_RealisticAgentResponse(t *testing.T) {
	// Simulates an agent response containing multiple PII classes,
	// like a real customer-service response leaking too much.
	input := `Your account holder is joe@intentgate.app, registered at IP 192.168.1.42.
Their primary IBAN is NL91 ABNA 0417 1643 00. Phone on file: +31 6 12345678.
Last payment was on a card ending in 4012 8888 8888 1881.`

	d := NewDetector(nil) // all classes
	matches := d.Detect(input)

	// Verify we caught at least one of each expected class
	got := make(map[Class]bool)
	for _, m := range matches {
		got[m.Class] = true
	}
	required := []Class{ClassEmail, ClassIPv4, ClassIBAN, ClassPhoneIntl, ClassCreditCard}
	for _, c := range required {
		if !got[c] {
			t.Errorf("expected at least one match for class %s in realistic input, got none", c)
		}
	}

	// Redact and verify nothing identifiable leaks through
	out, counts := Redact(input, matches)
	leaks := []string{"joe@intentgate.app", "192.168.1.42", "NL91", "+31 6", "4012 8888"}
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Errorf("leak after redaction: %q remained in output", leak)
		}
	}
	t.Logf("Realistic redaction counts: %v", counts)
}

// TestDetector_CoalesceOverlappingClasses verifies that when two
// regex classes match the same byte range (e.g. 9-digit BSN that
// also matches a generic phone_intl regex), the higher-priority
// class wins and only one match is returned. Lab production verified
// this bug: redacting "BSN-123456782" produced "BSN-[REDACTED:phone_intl]:bsn]"
// before the fix, then "BSN-[REDACTED:bsn]" after.
func TestDetector_CoalesceOverlappingClasses(t *testing.T) {
	d := NewDetector(nil) // all built-ins
	matches := d.Detect("national_id: BSN-123456782 trailing")

	// We expect at most one match covering the 9-digit substring.
	// (Other built-ins may add unrelated zero-length matches but the
	// 123456782 span itself should produce exactly one Match.)
	var nineDigit []Match
	for _, m := range matches {
		if m.Value == "123456782" {
			nineDigit = append(nineDigit, m)
		}
	}
	if len(nineDigit) != 1 {
		t.Fatalf("expected 1 match for '123456782', got %d: %+v", len(nineDigit), nineDigit)
	}
	if nineDigit[0].Class != ClassBSN {
		t.Errorf("expected BSN class (validator-having) to win, got %s", nineDigit[0].Class)
	}

	// Redaction should produce a single clean marker, not nested ones.
	out, counts := Redact("BSN-123456782", matches)
	if strings.Contains(out, ":bsn]") && !strings.HasSuffix(out, "[REDACTED:bsn]") {
		t.Errorf("nested-marker artefact still present: %q", out)
	}
	if counts[ClassBSN] != 1 {
		t.Errorf("expected BSN count 1, got %d", counts[ClassBSN])
	}
	if counts[ClassPhoneIntl] != 0 {
		t.Errorf("phone_intl should be coalesced away on BSN range, got count %d", counts[ClassPhoneIntl])
	}
}
