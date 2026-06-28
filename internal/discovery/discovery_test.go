package discovery

import (
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

func TestAggregate(t *testing.T) {
	events := []audit.Event{
		{Timestamp: "2026-06-01T10:00:00Z", AgentID: "refund-bot", Tool: "payment-api", Decision: "allow", SessionID: "s1", Tenant: "acme"},
		{Timestamp: "2026-06-01T10:05:00Z", AgentID: "refund-bot", Tool: "payment-api", Decision: "block", SessionID: "s1", Tenant: "acme"},
		{Timestamp: "2026-06-01T11:00:00Z", AgentID: "refund-bot", Tool: "orders", Decision: "allow", SessionID: "s2", Tenant: "acme"},
		{Timestamp: "2026-06-01T09:00:00Z", AgentID: "doc-bot", Tool: "sharepoint", Decision: "allow", SessionID: "s3", Tenant: "acme"},
		{Timestamp: "2026-06-01T12:00:00Z", AgentID: "", Tool: "mystery", Decision: "allow"},
	}

	agents := Aggregate(events)
	if len(agents) != 3 {
		t.Fatalf("want 3 agents, got %d", len(agents))
	}

	// Most recently seen first → the empty-id (unknown) agent at 12:00.
	if agents[0].AgentID != "" {
		t.Errorf("want unknown agent first (most recent), got %q", agents[0].AgentID)
	}
	if !hasSignal(agents[0].RiskSignals, SignalUnknownID) {
		t.Errorf("unknown agent should carry unknown-identity signal: %v", agents[0].RiskSignals)
	}

	var refund *ObservedAgent
	for i := range agents {
		if agents[i].AgentID == "refund-bot" {
			refund = &agents[i]
		}
	}
	if refund == nil {
		t.Fatal("refund-bot not found")
	}
	if refund.Calls != 3 {
		t.Errorf("refund-bot calls: want 3, got %d", refund.Calls)
	}
	if refund.Blocked != 1 {
		t.Errorf("refund-bot blocked: want 1, got %d", refund.Blocked)
	}
	if refund.SessionCount != 2 {
		t.Errorf("refund-bot sessions: want 2, got %d", refund.SessionCount)
	}
	if len(refund.Tools) != 2 {
		t.Errorf("refund-bot tools: want 2, got %v", refund.Tools)
	}
	if !hasSignal(refund.RiskSignals, SignalPayment) {
		t.Errorf("refund-bot should carry payment signal: %v", refund.RiskSignals)
	}
	if refund.FirstSeen != "2026-06-01T10:00:00Z" {
		t.Errorf("refund-bot first_seen wrong: %s", refund.FirstSeen)
	}
	if refund.LastSeen != "2026-06-01T11:00:00Z" {
		t.Errorf("refund-bot last_seen wrong: %s", refund.LastSeen)
	}
}

func TestAggregateEmpty(t *testing.T) {
	if got := Aggregate(nil); len(got) != 0 {
		t.Errorf("empty input should yield no agents, got %d", len(got))
	}
}

func hasSignal(sigs []string, want string) bool {
	for _, s := range sigs {
		if s == want {
			return true
		}
	}
	return false
}
