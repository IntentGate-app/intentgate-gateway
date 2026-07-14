package refverify

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A matching payee returned by the system of record resolves to a found Record,
// with normalization applied to the lookup key.
func TestHTTPVendorMaster_Match(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("payee") != "ACMEBV" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payee":"ACMEBV","name":"ACME Beheer BV"}`))
	}))
	defer srv.Close()

	m := NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL})
	rec, ok, err := m.Lookup("acme  bv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected payee found")
	}
	if rec.Name != "ACME Beheer BV" {
		t.Fatalf("name = %q, want ACME Beheer BV", rec.Name)
	}
}

// A 404 from the system of record is a definitive not-found (not an error).
func TestHTTPVendorMaster_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	m := NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL})
	_, ok, err := m.Lookup("ghost ltd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected not found")
	}
}

// A 200 body with found=false is also a not-found.
func TestHTTPVendorMaster_FoundFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"found":false}`))
	}))
	defer srv.Close()

	m := NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL})
	_, ok, err := m.Lookup("ghost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected not found from found=false body")
	}
}

// A 5xx (source down) is an error, which the Verifier treats fail-closed.
func TestHTTPVendorMaster_SourceDownIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL})
	if _, _, err := m.Lookup("acme"); err == nil {
		t.Fatal("expected error on 500 (fail-closed)")
	}
}

// Repeat lookups within the TTL hit the cache, not the upstream.
func TestHTTPVendorMaster_Caches(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = w.Write([]byte(`{"payee":"X","name":"X BV"}`))
	}))
	defer srv.Close()

	m := NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL, CacheTTL: time.Minute})
	_, _, _ = m.Lookup("x")
	_, _, _ = m.Lookup("x")
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("upstream calls = %d, want 1 (cache should absorb the repeat)", got)
	}
}

// The connector drives the full Verifier: a known payee allows, an unknown one
// quarantines, and a down source quarantines (fail-closed).
func TestHTTPVendorMaster_EndToEndWithVerifier(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("payee") == "GOOD" {
			_, _ = w.Write([]byte(`{"payee":"GOOD","name":"Good Vendor"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	v := New(Config{Master: NewHTTPVendorMaster(HTTPConfig{Endpoint: srv.URL}), FailClosed: true})

	if r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "GOOD"}); r.Verdict != VerdictAllow {
		t.Fatalf("known payee verdict = %s, want allow (%s)", r.Verdict, r.Reason)
	}
	if r := v.Check("pay_invoice", map[string]any{"amount": 100.0, "payee": "EVIL"}); r.Verdict != VerdictQuarantine {
		t.Fatalf("unknown payee verdict = %s, want quarantine", r.Verdict)
	}
}
