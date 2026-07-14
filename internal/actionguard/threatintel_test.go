package actionguard

import (
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// A payment to a threat-intel denied destination is blocked outright.
func TestThreatFeed_DenyDestinationBlocks(t *testing.T) {
	feed, err := NewThreatFeed([]string{"EvilCorp Ltd"}, nil, nil)
	if err != nil {
		t.Fatalf("build feed: %v", err)
	}
	g := New(Config{Feed: feed})
	r := g.Check("sess1", "pay_invoice", map[string]any{"amount": 100.0, "payee": "evilcorp  ltd"})
	if r.Verdict != VerdictBlock {
		t.Fatalf("verdict = %s, want block (rule %s)", r.Verdict, r.Rule)
	}
	if r.Rule != "threat.deny_destination" {
		t.Fatalf("rule = %s, want threat.deny_destination", r.Rule)
	}
}

// A call whose tool matches a denied pattern is blocked.
func TestThreatFeed_DenyToolBlocks(t *testing.T) {
	feed, err := NewThreatFeed(nil, []string{"(?i)wire_transfer_external"}, nil)
	if err != nil {
		t.Fatalf("build feed: %v", err)
	}
	g := New(Config{Feed: feed})
	r := g.Check("sess1", "Wire_Transfer_External", map[string]any{"amount": 100.0})
	if r.Verdict != VerdictBlock || r.Rule != "threat.deny_tool" {
		t.Fatalf("verdict = %s rule = %s, want block/threat.deny_tool", r.Verdict, r.Rule)
	}
}

// A known-bad ordered sequence (create then pay) escalates when completed.
func TestThreatFeed_BadSequenceEscalates(t *testing.T) {
	feed, err := NewThreatFeed(nil, nil, [][]actionir.Op{{actionir.OpCreate, actionir.OpPay}})
	if err != nil {
		t.Fatalf("build feed: %v", err)
	}
	g := New(Config{Feed: feed})
	// Step 1: create a supplier (records history, allowed).
	if r := g.Check("sess1", "create_supplier", map[string]any{"name": "New Vendor BV"}); r.Verdict != VerdictAllow {
		t.Fatalf("create verdict = %s, want allow", r.Verdict)
	}
	// Step 2: a payment now completes the create->pay chain.
	r := g.Check("sess1", "pay_invoice", map[string]any{"amount": 100.0, "payee": "Someone Else"})
	if r.Verdict != VerdictEscalate || r.Rule != "threat.bad_sequence" {
		t.Fatalf("verdict = %s rule = %s, want escalate/threat.bad_sequence", r.Verdict, r.Rule)
	}
}

// With no feed configured, behaviour is unchanged (a benign read allows).
func TestThreatFeed_NoFeedNoOp(t *testing.T) {
	g := New(Config{})
	if r := g.Check("sess1", "get_record", map[string]any{"id": "1"}); r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow with no feed", r.Verdict)
	}
}

// An invalid deny-tool regex is reported at build time.
func TestThreatFeed_InvalidPattern(t *testing.T) {
	if _, err := NewThreatFeed(nil, []string{"("}, nil); err == nil {
		t.Fatal("expected error on invalid regex")
	}
}
