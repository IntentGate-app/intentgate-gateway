package effectpreview

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// A payment previews as an irreversible money movement with the amount and payee.
func TestCompute_Payment(t *testing.T) {
	p := Compute("pay_invoice", map[string]any{"amount": 100.0, "payee": "ACME BV"}, nil)
	if p.Op != actionir.OpPay {
		t.Fatalf("op = %s, want pay", p.Op)
	}
	if p.MagnitudeCents != 10000 {
		t.Fatalf("magnitude = %d, want 10000", p.MagnitudeCents)
	}
	if !strings.Contains(p.BlastRadius, "payment") || !strings.Contains(p.BlastRadius, "ACME BV") {
		t.Fatalf("blast radius = %q, want it to mention the payment and payee", p.BlastRadius)
	}
}

// A delete previews as irreversible with a non-empty blast radius.
func TestCompute_Delete(t *testing.T) {
	p := Compute("delete_invoice", map[string]any{"id": "42"}, nil)
	if p.Op != actionir.OpDelete {
		t.Fatalf("op = %s, want delete", p.Op)
	}
	if p.Reversible {
		t.Fatal("delete should preview as irreversible")
	}
	if !strings.Contains(strings.ToLower(p.BlastRadius), "delete") {
		t.Fatalf("blast radius = %q, want it to mention delete", p.BlastRadius)
	}
}

// The row-count estimate is reflected in the summary.
func TestSummarize_DeleteWithRows(t *testing.T) {
	n := int64(4200)
	p := Preview{Op: actionir.OpDelete, Resource: "invoices", EstimatedRows: &n}
	got := summarize(p)
	if !strings.Contains(got, "4200") || !strings.Contains(got, "invoices") {
		t.Fatalf("summary = %q, want it to mention 4200 invoices", got)
	}
}

// The HTTP provider parses a {"count": N} response from a read-only endpoint.
func TestHTTPProvider_Count(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, _ = w.Write([]byte(`{"count":4200}`))
	}))
	defer srv.Close()

	prov := NewHTTPProvider(HTTPProviderConfig{Endpoint: srv.URL})
	n, err := prov.CountAffected("invoices", map[string]any{"where": "region=EU"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4200 {
		t.Fatalf("count = %d, want 4200", n)
	}
}
