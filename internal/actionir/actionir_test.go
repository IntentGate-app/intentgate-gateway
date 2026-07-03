package actionir

import "testing"

// The whole point of the resolver: calls that LOOK different but DO the same
// thing must resolve to the same effect, so one policy cannot be evaded by
// obfuscation or number-formatting drift.

func TestResolve_PayOverLimit(t *testing.T) {
	ir := Resolve("pay_invoice", map[string]any{"amount": 6000.0, "payee": "ACME BV"})
	if ir.Op != OpPay {
		t.Fatalf("op = %s, want pay", ir.Op)
	}
	if ir.MagnitudeCents != 600000 {
		t.Fatalf("cents = %d, want 600000", ir.MagnitudeCents)
	}
	if ir.Reversible {
		t.Fatalf("pay must be irreversible")
	}
	if ir.Destination != "ACME BV" {
		t.Fatalf("dest = %q, want ACME BV", ir.Destination)
	}
}

// Amount drift: every one of these is 5000.00 and must resolve identically.
func TestResolve_AmountDriftResistant(t *testing.T) {
	cases := []any{5000.0, 5000, "5000", "5,000", "5_000", "5 000", "EUR 5000", "5.000,00"}
	for _, amt := range cases {
		ir := Resolve("pay", map[string]any{"amount": amt})
		if ir.MagnitudeCents != 500000 {
			t.Errorf("amount %v: cents = %d, want 500000", amt, ir.MagnitudeCents)
		}
	}
}

// Destructive verb hidden by quoting / spacing must still resolve to delete.
func TestResolve_ObfuscatedDelete(t *testing.T) {
	for _, tool := range []string{"delete_orders", "de''lete_orders", "d-e-l-e-t-e orders", "DELETE orders"} {
		ir := Resolve(tool, nil)
		if ir.Op != OpDelete {
			t.Errorf("tool %q: op = %s, want delete", tool, ir.Op)
		}
		if ir.Reversible {
			t.Errorf("tool %q: delete must be irreversible", tool)
		}
	}
}

// Base64-encoded destructive verb must be decoded and resolve to delete.
func TestResolve_Base64Delete(t *testing.T) {
	// base64("drop_database") = ZHJvcF9kYXRhYmFzZQ==
	ir := Resolve("ZHJvcF9kYXRhYmFzZQ==", nil)
	if ir.Op != OpDelete {
		t.Fatalf("op = %s, want delete", ir.Op)
	}
	if !contains(ir.Signals, "decoded_base64") {
		t.Fatalf("signals = %v, want decoded_base64", ir.Signals)
	}
	if ir.Resource != "database" {
		t.Fatalf("resource = %q, want database", ir.Resource)
	}
}

// A destructive verb hidden inside an argument (not the tool name) is caught.
func TestResolve_DangerInArg(t *testing.T) {
	ir := Resolve("run_query", map[string]any{"sql": "DROP TABLE orders"})
	if ir.Op != OpDelete {
		t.Fatalf("op = %s, want delete", ir.Op)
	}
}

func TestResolve_Unbounded(t *testing.T) {
	ir := Resolve("delete_records", map[string]any{"scope": "all"})
	if ir.Scope != ScopeUnbounded {
		t.Fatalf("scope = %s, want unbounded", ir.Scope)
	}
}

func TestResolve_ReadIsReversible(t *testing.T) {
	ir := Resolve("read_invoice", map[string]any{"invoice_id": "INV-1"})
	if ir.Op != OpRead {
		t.Fatalf("op = %s, want read", ir.Op)
	}
	if !ir.Reversible {
		t.Fatalf("read must be reversible")
	}
	if ir.Scope != ScopeBounded {
		t.Fatalf("scope = %s, want bounded (has an id filter)", ir.Scope)
	}
}

// Creating a supplier is what enables the invoice-fraud chain; it must be
// classified as create/supplier so a plan-level rule can later correlate it.
func TestResolve_CreateSupplier(t *testing.T) {
	ir := Resolve("create_supplier", map[string]any{"name": "Ghost Ltd"})
	if ir.Op != OpCreate {
		t.Fatalf("op = %s, want create", ir.Op)
	}
	if ir.Resource != "supplier" {
		t.Fatalf("resource = %q, want supplier", ir.Resource)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
