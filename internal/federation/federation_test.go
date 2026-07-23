package federation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleSet() []Sample {
	return []Sample{
		{Decision: "allow", Check: "capability", Agent: "agent-alpha", Tool: "sap_create_order", Session: "s1", EventID: "evt-aaaa", ResultHash: "rh-aaaa"},
		{Decision: "allow", Check: "policy", Agent: "agent-alpha", Tool: "sap_create_order", Session: "s1", EventID: "evt-bbbb", ResultHash: "rh-bbbb"},
		{Decision: "block", Check: "intent", Agent: "agent-beta", Tool: "send_email", Session: "s2", EventID: "evt-cccc", ResultHash: "rh-cccc"},
		{Decision: "escalate", Check: "budget", Agent: "agent-beta", Tool: "wire_transfer", Session: "s2", EventID: "evt-dddd", ResultHash: "rh-dddd"},
		{Decision: "allow", Check: "capability", Agent: "agent-gamma", Tool: "read_invoice", Session: "s3", EventID: "evt-eeee", ResultHash: "rh-eeee"},
	}
}

func TestSummarizeCountsAndCardinalities(t *testing.T) {
	agg := Summarize(sampleSet())
	if agg.Decisions.Total != 5 {
		t.Fatalf("total = %d, want 5", agg.Decisions.Total)
	}
	if agg.Decisions.Allow != 3 || agg.Decisions.Deny != 1 || agg.Decisions.Hold != 1 {
		t.Errorf("decisions = %+v, want allow 3 / deny 1 / hold 1", agg.Decisions)
	}
	if agg.Agents != 3 {
		t.Errorf("distinct agents = %d, want 3", agg.Agents)
	}
	if agg.Tools != 4 {
		t.Errorf("distinct tools = %d, want 4", agg.Tools)
	}
	if agg.Sessions != 3 {
		t.Errorf("distinct sessions = %d, want 3", agg.Sessions)
	}
	if agg.ByCheck["capability"] != 2 || agg.ByCheck["intent"] != 1 {
		t.Errorf("by_check = %v, want capability 2 / intent 1", agg.ByCheck)
	}
}

func TestSummarizeEmptyIsZeroNotNil(t *testing.T) {
	agg := Summarize(nil)
	if agg.ByCheck == nil {
		t.Fatal("ByCheck must be a non-nil map so a rollup always has an object")
	}
	if agg.Decisions.Total != 0 || agg.Agents != 0 {
		t.Errorf("empty aggregate should be all zero, got %+v", agg)
	}
}

// TestRollupCarriesNoRawIdentifiers is the residency guard: the raw agent ids,
// tool names, and session ids that go INTO Summarize must not appear ANYWHERE in
// the marshaled rollup that leaves the node. Only counts and hashes may survive.
func TestRollupCarriesNoRawIdentifiers(t *testing.T) {
	samples := sampleSet()
	agg := Summarize(samples)
	from := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	head := WindowDigest(samples)
	r := Build("node-eu-west", "acme", from, to, agg, head, to)
	if err := Sign(&r, RollupKeyID, []byte("test-master-key-0123456789")); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	wire := string(raw)
	forbidden := []string{
		"agent-alpha", "agent-beta", "agent-gamma",
		"sap_create_order", "send_email", "wire_transfer", "read_invoice",
		"s1", "s2", "s3",
		"evt-aaaa", "evt-bbbb", "evt-cccc", "evt-dddd", "evt-eeee",
		"rh-aaaa", "rh-bbbb", "rh-cccc", "rh-dddd", "rh-eeee",
	}
	for _, f := range forbidden {
		if strings.Contains(wire, f) {
			t.Errorf("rollup wire form leaks raw identifier %q: %s", f, wire)
		}
	}
	// It MUST still carry the safe things.
	if !strings.Contains(wire, "node-eu-west") || !strings.Contains(wire, head) {
		t.Errorf("rollup should carry node id and audit head hash: %s", wire)
	}
	if !strings.Contains(wire, "capability") {
		t.Errorf("rollup should carry IntentGate check-name breakdown: %s", wire)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	key := []byte("federation-master-key-abcdefabcdef")
	agg := Summarize(sampleSet())
	now := time.Now()
	r := Build("node-1", "", now.Add(-time.Hour), now, agg, "deadbeef", now)
	if err := Sign(&r, RollupKeyID, key); err != nil {
		t.Fatal(err)
	}
	if r.KeyID != RollupKeyID {
		t.Errorf("key id = %q, want %q", r.KeyID, RollupKeyID)
	}
	if ok, why := Verify(r, key); !ok {
		t.Fatalf("fresh rollup should verify, got %q", why)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	key := []byte("federation-master-key-abcdefabcdef")
	agg := Summarize(sampleSet())
	now := time.Now()
	r := Build("node-1", "", now.Add(-time.Hour), now, agg, "deadbeef", now)
	if err := Sign(&r, RollupKeyID, key); err != nil {
		t.Fatal(err)
	}
	// Flip a single count: an inflated allow number must break verification.
	r.Decisions.Allow += 1
	if ok, why := Verify(r, key); ok {
		t.Fatalf("tampered rollup must not verify, got ok (why=%q)", why)
	}
	// Wrong key must also fail.
	if err := Sign(&r, RollupKeyID, key); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(r, []byte("the-wrong-key-0000000000000000")); ok {
		t.Fatal("rollup must not verify under the wrong key")
	}
}

func TestWindowDigestDeterministicAndSensitive(t *testing.T) {
	a := WindowDigest(sampleSet())
	b := WindowDigest(sampleSet())
	if a != b {
		t.Fatal("digest must be deterministic for the same window")
	}
	if a == "" {
		t.Fatal("digest of a non-empty window must be non-empty")
	}
	// Changing one result hash must change the digest (tamper sensitivity).
	s := sampleSet()
	s[0].ResultHash = "rh-changed"
	if WindowDigest(s) == a {
		t.Fatal("digest must change when a result hash changes")
	}
	// A window with no ids/hashes still yields a stable, valid digest.
	if WindowDigest([]Sample{{Decision: "allow"}}) == "" {
		t.Fatal("empty-material digest should still be non-empty")
	}
}

func TestVerifyUnsigned(t *testing.T) {
	agg := Summarize(nil)
	now := time.Now()
	r := Build("node-1", "", now, now, agg, "", now)
	if ok, why := Verify(r, []byte("k")); ok || why != "unsigned" {
		t.Errorf("unsigned rollup should report unsigned, got ok=%v why=%q", ok, why)
	}
}
