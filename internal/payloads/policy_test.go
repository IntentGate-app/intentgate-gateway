package payloads

import (
	"testing"
	"time"
)

// The whole design rests on capture being off unless someone turned it on.
func TestZeroPolicyCapturesNothing(t *testing.T) {
	var p Policy
	for _, tool := range []string{"read_invoice", "agent:agent-finance-1", "*"} {
		if p.ShouldCapture(tool) {
			t.Fatalf("zero policy captured %q", tool)
		}
	}
}

// Listing tools without enabling must not capture. Two switches, both
// required: an operator staging a config should not start retaining customer
// data the moment they type a tool name.
func TestToolsWithoutEnabledCapturesNothing(t *testing.T) {
	p := Policy{Tools: []string{"*"}}
	if p.ShouldCapture("read_invoice") {
		t.Fatal("captured with Enabled=false")
	}
}

func TestExactAndPatternMatch(t *testing.T) {
	p := Policy{Enabled: true, Tools: []string{"read_invoice", "list_*"}}
	cases := map[string]bool{
		"read_invoice":   true,
		"list_accounts":  true,
		"list_":          true,
		"transfer_funds": false,
		"read_invoices":  false, // exact means exact
	}
	for tool, want := range cases {
		if got := p.ShouldCapture(tool); got != want {
			t.Errorf("ShouldCapture(%q) = %v, want %v", tool, got, want)
		}
	}
}

// Agent-to-agent responses must be selectable on their own. Capturing every
// inter-agent hand-off while capturing no tool output is a legitimate and
// probably common posture: the hand-offs are the part nobody can otherwise
// see, and they carry less customer data than tool results do.
func TestAgentPrefixIsSelectableSeparately(t *testing.T) {
	p := Policy{Enabled: true, Tools: []string{"agent:*"}}
	if !p.ShouldCapture("agent:agent-finance-1") {
		t.Fatal("did not capture an agent-to-agent call")
	}
	if p.ShouldCapture("transfer_funds") {
		t.Fatal("agent:* leaked into tool capture")
	}
}

func TestStarCapturesEverything(t *testing.T) {
	p := Policy{Enabled: true, Tools: []string{"*"}}
	if !p.ShouldCapture("anything") || !p.ShouldCapture("agent:x") {
		t.Fatal("* did not capture")
	}
}

// A zero TTL in a config file must not mean "keep forever", and a zero size
// cap must not mean "no limit". Both are the failure mode where an oversight
// quietly becomes a permanent copy of customer data.
func TestNormaliseRefusesUnboundedDefaults(t *testing.T) {
	p := Policy{Enabled: true}.Normalise()
	if p.TTL != DefaultTTL {
		t.Fatalf("TTL = %v, want %v", p.TTL, DefaultTTL)
	}
	if p.MaxBytes != DefaultMaxBytes {
		t.Fatalf("MaxBytes = %d, want %d", p.MaxBytes, DefaultMaxBytes)
	}
}

func TestNormaliseKeepsExplicitValues(t *testing.T) {
	p := Policy{Enabled: true, TTL: time.Hour, MaxBytes: 10}.Normalise()
	if p.TTL != time.Hour || p.MaxBytes != 10 {
		t.Fatalf("normalise overwrote explicit values: %+v", p)
	}
}

func TestTruncateCopiesRatherThanReslices(t *testing.T) {
	p := Policy{MaxBytes: 4}
	src := []byte("abcdefgh")
	out, cut := p.Truncate(src)
	if !cut || string(out) != "abcd" {
		t.Fatalf("out=%q cut=%v", out, cut)
	}
	// Mutating the caller's buffer must not change what was stored.
	src[0] = 'Z'
	if string(out) != "abcd" {
		t.Fatalf("stored body aliased the caller's buffer: %q", out)
	}
}

func TestTruncateLeavesSmallBodiesAlone(t *testing.T) {
	out, cut := Policy{MaxBytes: 100}.Truncate([]byte("small"))
	if cut || string(out) != "small" {
		t.Fatalf("out=%q cut=%v", out, cut)
	}
}
