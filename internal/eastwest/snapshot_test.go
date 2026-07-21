package eastwest

import (
	"testing"
	"time"
)

// Snapshot feeds the admin GET, and the console saves back what it read. So
// anything Snapshot drops is deleted from the estate on the next save, with no
// error and no visible symptom. These tests exist to make that class of loss
// impossible to reintroduce quietly.

func TestSnapshotRoundTripsRules(t *testing.T) {
	expires := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:       "agent-procure-1",
			To:         "agent-finance-1",
			Purpose:    "confirm invoice totals before raising a PO",
			Owner:      "procurement-platform",
			ApprovedBy: "risk@example.com",
			ExpiresAt:  expires,
		}},
	})

	snap := g.Snapshot()
	if len(snap.Rules) != 1 {
		t.Fatalf("snapshot lost the rules: got %d, want 1", len(snap.Rules))
	}
	got := snap.Rules[0]
	if got.Purpose == "" || got.Owner == "" || got.ApprovedBy == "" {
		t.Errorf("snapshot dropped governance metadata: %+v", got)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("expiry not preserved: got %v, want %v", got.ExpiresAt, expires)
	}
}

// The snapshot must be a copy. Handing out the live slice lets a caller mutate
// the ruleset the gateway is enforcing, without going through Replace.
func TestSnapshotRulesAreACopy(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules:           []Rule{{From: "agent-a", To: "agent-b", Purpose: "original"}},
	})

	snap := g.Snapshot()
	snap.Rules[0].Purpose = "mutated"
	snap.Rules[0].To = "agent-elsewhere"

	if again := g.Snapshot(); again.Rules[0].Purpose != "original" {
		t.Error("mutating a snapshot changed the live ruleset")
	}
	// And the guard still enforces the original pair.
	if res := g.Check("agent-a", "", "agent:agent-b"); res.Verdict != VerdictAllow {
		t.Errorf("live rule was altered through the snapshot, got %q", res.Verdict)
	}
}

// ObserveOnly reported as false while the gateway is observing means every
// console surface tells the operator their estate is segmented when nothing is
// being stopped. That is the most dangerous single field to lose.
func TestSnapshotPreservesObserveOnly(t *testing.T) {
	g := New(Config{AgentToolPrefix: "agent:", ObserveOnly: true})
	if !g.Snapshot().ObserveOnly {
		t.Fatal("snapshot reported enforcing while the guard is in observe mode")
	}

	g2 := New(Config{AgentToolPrefix: "agent:"})
	if g2.Snapshot().ObserveOnly {
		t.Fatal("snapshot reported observe mode on an enforcing guard")
	}
}

func TestSnapshotRoundTripsPairsAndLabels(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Zones:           map[string]string{"agent-finance-1": "finance"},
		AllowedPairs:    [][2]string{{"agent-procure-1", "agent-finance-1"}},
		AllowedEdges:    [][2]string{{"procurement", "finance"}},
	})

	snap := g.Snapshot()
	if len(snap.AllowedPairs) != 1 || len(snap.AllowedEdges) != 1 || len(snap.Zones) != 1 {
		t.Fatalf("snapshot lost config: pairs=%d edges=%d zones=%d",
			len(snap.AllowedPairs), len(snap.AllowedEdges), len(snap.Zones))
	}
	if snap.AgentToolPrefix != "agent:" {
		t.Errorf("prefix not preserved: %q", snap.AgentToolPrefix)
	}
}
