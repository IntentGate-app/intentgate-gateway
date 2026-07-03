package actionguard

import "testing"

func newGuard() *Guard { return New(DefaultConfig()) }

// Mandatory hold: an irreversible payment over the threshold pauses for a human.
func TestCheck_HighValueIrreversibleEscalates(t *testing.T) {
	g := newGuard()
	r := g.Check("s1", "pay_invoice", map[string]any{"amount": 6000.0, "payee": "ACME BV"})
	if r.Verdict != VerdictEscalate {
		t.Fatalf("verdict = %s, want escalate (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "hold.high_value_irreversible" {
		t.Fatalf("rule = %s", r.Rule)
	}
}

// Under the threshold, a normal payment is allowed.
func TestCheck_SmallPaymentAllowed(t *testing.T) {
	g := newGuard()
	r := g.Check("s2", "pay_invoice", map[string]any{"amount": 100.0, "payee": "ACME BV"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", r.Verdict)
	}
}

// Mandatory hold: an unbounded delete is blocked outright.
func TestCheck_UnboundedDeleteBlocked(t *testing.T) {
	g := newGuard()
	r := g.Check("s3", "delete_records", map[string]any{"scope": "all"})
	if r.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want block (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "hold.unbounded_delete" {
		t.Fatalf("rule = %s", r.Rule)
	}
}

// Plan-level (#28): create a supplier, then pay it in the same session. Each
// call is individually legal and under the money threshold, but the SEQUENCE
// is the invoice-fraud pattern, so the payment must escalate.
func TestCheck_PlanLevelInvoiceFraud(t *testing.T) {
	g := newGuard()

	if r := g.Check("s4", "create_supplier", map[string]any{"name": "Ghost Ltd"}); r.Verdict != VerdictAllow {
		t.Fatalf("create: verdict = %s, want allow", r.Verdict)
	}
	// Small payment, well under the 5000 threshold, so only the plan rule can catch it.
	r := g.Check("s4", "pay_invoice", map[string]any{"amount": 100.0, "payee": "Ghost Ltd"})
	if r.Verdict != VerdictEscalate {
		t.Fatalf("pay: verdict = %s, want escalate", r.Verdict)
	}
	if r.Rule != "plan.pay_to_self_created_party" {
		t.Fatalf("rule = %s, want plan.pay_to_self_created_party", r.Rule)
	}
}

// A payment to a party NOT created this session, under threshold, is allowed.
func TestCheck_PayToKnownPartyAllowed(t *testing.T) {
	g := newGuard()
	g.Check("s5", "create_supplier", map[string]any{"name": "Alpha BV"})
	r := g.Check("s5", "pay_invoice", map[string]any{"amount": 100.0, "payee": "Beta BV"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (rule %s)", r.Verdict, r.Rule)
	}
}

// Sessions are isolated: a supplier created in one session does not taint another.
func TestCheck_SessionsIsolated(t *testing.T) {
	g := newGuard()
	g.Check("a", "create_supplier", map[string]any{"name": "Ghost Ltd"})
	r := g.Check("b", "pay_invoice", map[string]any{"amount": 100.0, "payee": "Ghost Ltd"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("cross-session verdict = %s, want allow", r.Verdict)
	}
}

func TestCheck_ReadAllowed(t *testing.T) {
	g := newGuard()
	r := g.Check("s6", "read_invoice", map[string]any{"invoice_id": "INV-1"})
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", r.Verdict)
	}
}
