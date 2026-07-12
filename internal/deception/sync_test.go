package deception

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchDecoysParsesConsoleShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("missing/wrong bearer: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decoys":[{"id":"d1","name":"admin_payments","kind":"honey_tool","key":"admin_payments","pillar":"tool","on_trip":"contain"}]}`))
	}))
	defer srv.Close()

	decoys, err := FetchDecoys(context.Background(), srv.Client(), srv.URL, "tok")
	if err != nil {
		t.Fatalf("FetchDecoys: %v", err)
	}
	if len(decoys) != 1 || decoys[0].Key != "admin_payments" || decoys[0].Kind != HoneyTool || decoys[0].OnTrip != OnTripContain {
		t.Fatalf("unexpected decoys: %+v", decoys)
	}
}

func TestFetchDecoysNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := FetchDecoys(context.Background(), srv.Client(), srv.URL, "tok"); err == nil {
		t.Fatal("expected error on non-200")
	}
}

func TestSyncRegistrySwapAndSeed(t *testing.T) {
	seed := []Decoy{{ID: "s1", Name: "seed_tool", Kind: HoneyTool, Key: "seed_tool", OnTrip: OnTripContain}}
	r := NewSyncRegistry(seed)

	// Seeded set is live immediately.
	if _, ok := r.Match(Input{Tool: "seed_tool"}); !ok {
		t.Fatal("seed decoy should match before any sync")
	}

	// After a swap, the new set is live and the old one is gone.
	r.set([]Decoy{{ID: "n1", Name: "new_tool", Kind: HoneyTool, Key: "new_tool", OnTrip: OnTripContain}})
	if _, ok := r.Match(Input{Tool: "new_tool"}); !ok {
		t.Fatal("new decoy should match after set")
	}
	if _, ok := r.Match(Input{Tool: "seed_tool"}); ok {
		t.Fatal("old seed decoy should no longer match after set")
	}
}

func TestRunSyncKeepsLastKnownGoodOnError(t *testing.T) {
	// Server always 500s, so RunSync can never refresh; the seed must survive.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	seed := []Decoy{{ID: "s1", Name: "seed_tool", Kind: HoneyTool, Key: "seed_tool", OnTrip: OnTripContain}}
	r := NewSyncRegistry(seed)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	// interval longer than the ctx so we exercise exactly one failing refresh.
	r.RunSync(ctx, srv.Client(), srv.URL, "tok", time.Second, nil, nil)

	if _, ok := r.Match(Input{Tool: "seed_tool"}); !ok {
		t.Fatal("seed decoy must survive a failed sync (last-known-good)")
	}
}
