package siem

import (
	"context"
	"strings"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// capture is a fake downstream emitter that records what it receives
// and whether Stop was forwarded.
type capture struct {
	events  []audit.Event
	stopped bool
}

func (c *capture) Emit(_ context.Context, e audit.Event) { c.events = append(c.events, e) }
func (c *capture) Stop(context.Context) error            { c.stopped = true; return nil }

func TestIsFinding(t *testing.T) {
	cases := []struct {
		name string
		ev   audit.Event
		want bool
	}{
		{"block is a finding", audit.Event{Decision: audit.DecisionBlock}, true},
		{"escalate is a finding", audit.Event{Decision: audit.DecisionEscalate}, true},
		{"plain allow is not", audit.Event{Decision: audit.DecisionAllow}, false},
		{"allow with step-up is", audit.Event{Decision: audit.DecisionAllow, RequiresStepUp: true}, true},
	}
	for _, c := range cases {
		if got := IsFinding(c.ev); got != c.want {
			t.Errorf("%s: IsFinding = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildSummary(t *testing.T) {
	s := BuildSummary(audit.Event{
		Decision: audit.DecisionBlock,
		Tool:     "place_purchase_order",
		AgentID:  "agent-procure",
		Check:    "policy",
		Reason:   "amount over 5000 EUR",
	})
	for _, want := range []string{"BLOCK", "place_purchase_order", "agent-procure", "policy", "amount over 5000 EUR"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q missing %q", s, want)
		}
	}
}

func TestRoutingFindingsMode(t *testing.T) {
	inner := &capture{}
	r := NewRoutingEmitter(inner, ModeFindings)

	// A routine allow is dropped in findings mode.
	r.Emit(context.Background(), audit.Event{Decision: audit.DecisionAllow, Tool: "read_invoice", AgentID: "a1"})
	// A block passes and is stamped with a summary.
	r.Emit(context.Background(), audit.Event{Decision: audit.DecisionBlock, Tool: "transfer_funds", AgentID: "a1", Check: "policy", Reason: "denied"})

	if len(inner.events) != 1 {
		t.Fatalf("findings mode forwarded %d events, want 1", len(inner.events))
	}
	if inner.events[0].Summary == "" {
		t.Error("forwarded finding was not stamped with a summary")
	}
}

func TestRoutingAllModeStampsSummary(t *testing.T) {
	inner := &capture{}
	r := NewRoutingEmitter(inner, ModeAll)

	r.Emit(context.Background(), audit.Event{Decision: audit.DecisionAllow, Tool: "read_invoice", AgentID: "a1"})
	r.Emit(context.Background(), audit.Event{Decision: audit.DecisionBlock, Tool: "transfer_funds", AgentID: "a1"})

	if len(inner.events) != 2 {
		t.Fatalf("all mode forwarded %d events, want 2", len(inner.events))
	}
	for i, e := range inner.events {
		if e.Summary == "" {
			t.Errorf("event %d not stamped with a summary in all mode", i)
		}
	}
}

func TestRoutingForwardsStop(t *testing.T) {
	inner := &capture{}
	r := NewRoutingEmitter(inner, ModeFindings)
	s, ok := r.(interface{ Stop(context.Context) error })
	if !ok {
		t.Fatal("routing emitter does not implement Stop")
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}
	if !inner.stopped {
		t.Error("Stop was not forwarded to the wrapped sink")
	}
}

func TestParseEventMode(t *testing.T) {
	if ParseEventMode("", ModeFindings) != ModeFindings {
		t.Error("empty should return the default")
	}
	if ParseEventMode("ALL", ModeFindings) != ModeAll {
		t.Error("ALL should parse to ModeAll (case-insensitive)")
	}
	if ParseEventMode("findings", ModeAll) != ModeFindings {
		t.Error("findings should parse to ModeFindings")
	}
	if ParseEventMode("nonsense", ModeAll) != ModeAll {
		t.Error("unknown should return the default")
	}
}
