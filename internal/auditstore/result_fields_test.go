package auditstore

import (
	"context"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// The response-observability fields must survive a store round-trip. Without
// event_id on the persisted row the console has no key to resolve a call to
// its captured response, which is the whole point of retaining one.
func TestResultFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)

	e := newTestEvent(time.Now().UTC(), audit.DecisionAllow, "agent:agent-finance-1", "agent-procure-1")
	e.EventID = "evt-abc"
	e.ResultSHA256 = "deadbeef"
	e.ResultBytes = 1234
	e.ResultStored = true
	if err := s.Insert(ctx, e); err != nil {
		t.Fatalf("insert: %v", err)
	}

	out, err := s.Query(ctx, QueryFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 event, got %d", len(out))
	}
	got := out[0]
	if got.EventID != "evt-abc" {
		t.Fatalf("EventID = %q, want evt-abc: the payload drill-down has no join key", got.EventID)
	}
	if got.ResultSHA256 != "deadbeef" || got.ResultBytes != 1234 || !got.ResultStored {
		t.Fatalf("result fields lost: %+v", got)
	}
}

// These four fields are deliberately outside audit.canonicalEvent. If that
// ever changes, every existing deployment's hash chain breaks at the first row
// written after the upgrade — a silent, unrecoverable integrity failure. This
// test is the tripwire.
func TestResultFieldsDoNotBreakTheChain(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore(0)
	now := time.Now().UTC()

	// A chain that starts before capture existed and continues after it is
	// switched on, which is exactly the upgrade path a customer takes.
	plain := newTestEvent(now, audit.DecisionAllow, "read_invoice", "agent-a")
	if err := s.Insert(ctx, plain); err != nil {
		t.Fatalf("insert plain: %v", err)
	}
	withResult := newTestEvent(now.Add(time.Second), audit.DecisionAllow, "agent:agent-finance-1", "agent-a")
	withResult.EventID = "evt-1"
	withResult.ResultSHA256 = "cafebabe"
	withResult.ResultBytes = 99
	withResult.ResultStored = true
	if err := s.Insert(ctx, withResult); err != nil {
		t.Fatalf("insert with result: %v", err)
	}

	res, err := s.VerifyChain(ctx, VerifyFilter{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("chain broke once result fields were populated: %+v", res)
	}
	if res.Verified != 2 {
		t.Fatalf("verified %d rows, want 2", res.Verified)
	}
}
