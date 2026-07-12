package refverify

import (
	"errors"
	"path/filepath"
	"testing"
)

// master is a small static vendor master used across the table tests.
func master() *StaticVendorMaster {
	return NewStaticVendorMaster([]Record{
		{Payee: "ACME BV", Name: "ACME Beheer BV"},
		{Payee: "Globex NV", Name: "Globex Corporation NV"},
	})
}

func newVerifier() *Verifier {
	return New(Config{Master: master(), FailClosed: true})
}

// A payment to a payee that is in the vendor master is allowed.
func TestCheck_PayeeInMasterAllows(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "ACME BV"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.match" {
		t.Fatalf("rule = %s, want refverify.match", r.Rule)
	}
}

// Normalization is drift-resistant: differently-spaced/cased payee still matches.
func TestCheck_PayeeMatchNormalized(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "acme  bv"})
	if r.Verdict != VerdictAllow || r.Rule != "refverify.match" {
		t.Fatalf("verdict = %s rule = %s, want allow/refverify.match", r.Verdict, r.Rule)
	}
}

// A payment to a payee that is NOT in the master is quarantined.
func TestCheck_UnknownPayeeQuarantines(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "Ghost Ltd"})
	if r.Verdict != VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.payee_not_in_master" {
		t.Fatalf("rule = %s, want refverify.payee_not_in_master", r.Rule)
	}
}

// A known payee with a mismatched asserted name is quarantined (name-swap fraud).
func TestCheck_NameMismatchQuarantines(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{
		"amount":     100.0,
		"payee":      "ACME BV",
		"payee_name": "Totally Different Ltd",
	})
	if r.Verdict != VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.name_mismatch" {
		t.Fatalf("rule = %s, want refverify.name_mismatch", r.Rule)
	}
}

// A known payee with a matching asserted name is allowed.
func TestCheck_NameMatchAllows(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{
		"amount":     100.0,
		"payee":      "ACME BV",
		"payee_name": "acme beheer bv",
	})
	if r.Verdict != VerdictAllow || r.Rule != "refverify.match" {
		t.Fatalf("verdict = %s rule = %s, want allow/refverify.match", r.Verdict, r.Rule)
	}
}

// A non-payment call (a read) is ignored and allowed.
func TestCheck_NonPaymentAllowed(t *testing.T) {
	v := newVerifier()
	r := v.Check("read_invoice", map[string]any{"invoice_id": "INV-1"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.not_payment" {
		t.Fatalf("rule = %s, want refverify.not_payment", r.Rule)
	}
}

// errMaster is a fake VendorMaster whose reference source is down.
type errMaster struct{}

func (errMaster) Lookup(string) (Record, bool, error) {
	return Record{}, false, errors.New("SAP unreachable")
}

// When the reference source errors, the payment is quarantined (fail-closed).
func TestCheck_SourceErrorQuarantines(t *testing.T) {
	v := New(Config{Master: errMaster{}, FailClosed: true})
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "ACME BV"})
	if r.Verdict != VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.source_unavailable" {
		t.Fatalf("rule = %s, want refverify.source_unavailable", r.Rule)
	}
}

// A payment with no identifiable payee under fail-closed is quarantined.
func TestCheck_NoPayeeFailClosedQuarantines(t *testing.T) {
	v := newVerifier()
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0})
	if r.Verdict != VerdictQuarantine {
		t.Fatalf("verdict = %s, want quarantine (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "refverify.no_payee" {
		t.Fatalf("rule = %s, want refverify.no_payee", r.Rule)
	}
}

// With no reference source configured, fail-closed quarantines payments.
func TestCheck_NoSourceFailClosedQuarantines(t *testing.T) {
	v := New(Config{Master: nil, FailClosed: true})
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "ACME BV"})
	if r.Verdict != VerdictQuarantine || r.Rule != "refverify.no_source" {
		t.Fatalf("verdict = %s rule = %s, want quarantine/refverify.no_source", r.Verdict, r.Rule)
	}
}

// Below the min-cents threshold, a payment is allowed without verification.
func TestCheck_BelowThresholdAllows(t *testing.T) {
	v := New(Config{Master: master(), MinCents: 500000, FailClosed: true})
	r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "Ghost Ltd"})
	if r.Verdict != VerdictAllow || r.Rule != "refverify.below_threshold" {
		t.Fatalf("verdict = %s rule = %s, want allow/refverify.below_threshold", r.Verdict, r.Rule)
	}
}

// LoadConfigFile parses the JSON and folds aliases in as their own lookup keys.
func TestLoadConfigFile(t *testing.T) {
	records, err := LoadConfigFile(filepath.Join("testdata", "vendors.json"))
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if len(records) == 0 {
		t.Fatalf("no records loaded")
	}
	m := NewStaticVendorMaster(records)

	// Canonical payee resolves.
	if _, ok, _ := m.Lookup("ACME BV"); !ok {
		t.Fatalf("canonical payee ACME BV not found")
	}
	// An alias resolves to a record carrying the authoritative name.
	rec, ok, _ := m.Lookup("NL00ACME0000000000")
	if !ok {
		t.Fatalf("alias NL00ACME0000000000 not found")
	}
	if rec.Name != "ACME Beheer BV" {
		t.Fatalf("alias name = %q, want ACME Beheer BV", rec.Name)
	}

	// Using the loaded master end-to-end.
	v := New(Config{Master: m, FailClosed: true})
	if r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "Globex NV"}); r.Rule != "refverify.match" {
		t.Fatalf("Globex NV rule = %s, want refverify.match", r.Rule)
	}
}
