package eastwest

import (
	"testing"
	"time"
)

// A config written before Rule existed must keep enforcing exactly as it did.
// This is the test that lets an estate upgrade the gateway without touching
// its configuration.
func TestBarePairsStillAuthorize(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-1", "agent-finance-1"}},
	})

	if res := g.Check("agent-procure-1", "", "agent:agent-finance-1"); res.Verdict != VerdictAllow {
		t.Fatalf("bare pair should still allow, got %q (%s)", res.Verdict, res.Reason)
	}
	if res := g.Check("agent-support-1", "", "agent:agent-finance-1"); res.Verdict != VerdictDeny {
		t.Fatalf("unlisted caller should be denied, got %q", res.Verdict)
	}
}

func TestRuleAuthorizesLikeAPair(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:    "agent-procure-1",
			To:      "agent-finance-1",
			Purpose: "confirm invoice totals before raising a PO",
			Owner:   "procurement-platform",
		}},
	})

	if res := g.Check("agent-procure-1", "", "agent:agent-finance-1"); res.Verdict != VerdictAllow {
		t.Fatalf("rule should allow, got %q (%s)", res.Verdict, res.Reason)
	}
}

// Expiry is the field most likely to become decoration. If this test is ever
// deleted or weakened, the console is showing a governance control that does
// not govern.
func TestExpiredRuleDenies(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:      "agent-procure-1",
			To:        "agent-finance-1",
			ExpiresAt: past,
		}},
	})

	res := g.Check("agent-procure-1", "", "agent:agent-finance-1")
	if res.Verdict != VerdictDeny {
		t.Fatalf("expired rule must not authorize, got %q (%s)", res.Verdict, res.Reason)
	}
}

func TestUnexpiredRuleStillAuthorizes(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:      "agent-procure-1",
			To:        "agent-finance-1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}},
	})

	if res := g.Check("agent-procure-1", "", "agent:agent-finance-1"); res.Verdict != VerdictAllow {
		t.Fatalf("rule inside its window should allow, got %q", res.Verdict)
	}
}

// A pattern rule expires too. Easy to miss because patterns take a different
// branch in pairAllowed.
func TestExpiredPatternRuleDenies(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:      "agent-procure-*",
			To:        "agent-finance-1",
			ExpiresAt: time.Now().Add(-time.Minute),
		}},
	})

	if res := g.Check("agent-procure-4", "", "agent:agent-finance-1"); res.Verdict != VerdictDeny {
		t.Fatalf("expired pattern rule must not authorize, got %q", res.Verdict)
	}
}

func TestNeedsReview(t *testing.T) {
	now := time.Now()

	// Never approved by anyone: needs review from the moment it exists.
	if !(Rule{From: "a", To: "b"}).NeedsReview(now) {
		t.Error("an unapproved rule should need review")
	}
	// Approved, no review date: settled.
	approved := Rule{From: "a", To: "b", ApprovedBy: "risk@example.com"}
	if approved.NeedsReview(now) {
		t.Error("an approved rule with no review date should not need review")
	}
	// Approved but past its review date.
	due := approved
	due.ReviewBy = now.Add(-time.Hour)
	if !due.NeedsReview(now) {
		t.Error("a rule past its review date should need review")
	}
	// Approved, review date in future.
	future := approved
	future.ReviewBy = now.Add(time.Hour)
	if future.NeedsReview(now) {
		t.Error("a rule before its review date should not need review")
	}
}

// Review is governance, not enforcement: a rule due for review must keep
// working. The opposite would take production down on a calendar date.
func TestRuleDueForReviewStillAuthorizes(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Rules: []Rule{{
			From:     "agent-procure-1",
			To:       "agent-finance-1",
			ReviewBy: time.Now().Add(-30 * 24 * time.Hour),
		}},
	})

	if res := g.Check("agent-procure-1", "", "agent:agent-finance-1"); res.Verdict != VerdictAllow {
		t.Fatalf("an overdue review must not block the call, got %q", res.Verdict)
	}
}

// Both forms in one config, which is what an estate mid-migration looks like.
func TestPairsAndRulesCoexist(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-2", "agent-finance-1"}},
		Rules: []Rule{{
			From:       "agent-procure-3",
			To:         "agent-finance-1",
			ApprovedBy: "risk@example.com",
		}},
	})

	for _, caller := range []string{"agent-procure-2", "agent-procure-3"} {
		if res := g.Check(caller, "", "agent:agent-finance-1"); res.Verdict != VerdictAllow {
			t.Errorf("%s should be allowed, got %q", caller, res.Verdict)
		}
	}
	if res := g.Check("agent-procure-9", "", "agent:agent-finance-1"); res.Verdict != VerdictDeny {
		t.Error("an agent named by neither form should be denied")
	}
}
