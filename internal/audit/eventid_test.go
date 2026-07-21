package audit

import "testing"

func TestNewEventIDIsUniqueAndStableLength(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewEventID()
		if len(id) != 22 {
			t.Fatalf("id %q has length %d, want 22", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate id %q on iteration %d", id, i)
		}
		seen[id] = true
	}
}

// The canonical hash is an explicit struct mirror. If a new field ever reaches
// it, every chain already written stops verifying, because the canonical bytes
// of old events change too. This test pins that: adding EventID and the result
// fields to Event must leave the canonical form untouched.
func TestCanonicalHashIgnoresEventIDAndResultFields(t *testing.T) {
	base := Event{
		Timestamp:     "2026-07-21T10:00:00Z",
		EventName:     "tool_call",
		SchemaVersion: "1",
		Decision:      DecisionAllow,
		Tool:          "read_invoice",
		AgentID:       "agent-procure-1",
	}

	withExtras := base
	withExtras.EventID = NewEventID()
	withExtras.ResultSHA256 = "deadbeef"
	withExtras.ResultBytes = 4096
	withExtras.ResultStored = true

	a, err := CanonicalForHash(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalForHash(withExtras)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical form changed when result fields were set.\n"+
			"This breaks verification of every chain already written.\n"+
			"without: %s\nwith:    %s", a, b)
	}
}
