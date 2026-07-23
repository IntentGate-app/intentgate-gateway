package proofofintent

import (
	"testing"
	"time"
)

func sampleEntries() []Entry {
	return []Entry{
		{
			EventID: "dec_1", Ts: "2026-07-23T18:00:00Z", Agent: "agent-finance-1",
			Tool: "transfer_funds", Decision: "escalate", Check: "action_guard",
			Reason: "over_autonomous_threshold", IntentSummary: "Reconcile this month's invoices",
			ResultSHA256: "aa", PrevHash: "root", Hash: "h1",
		},
		{
			EventID: "dec_2", Ts: "2026-07-23T18:00:05Z", Agent: "agent-finance-1",
			Tool: "read_invoice", Decision: "allow", Check: "",
			Reason: "", IntentSummary: "Reconcile this month's invoices",
			ResultSHA256: "bb", PrevHash: "h1", Hash: "h2",
		},
	}
}

var key = []byte("test-master-key-32-bytes-long!!!")

func TestSignThenVerifyRoundTrips(t *testing.T) {
	b := Build("acme", "session-123", sampleEntries(), time.Unix(1000, 0))
	if err := Sign(&b, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	if b.Signature == "" {
		t.Fatal("expected a signature")
	}
	if b.KeyID != "mk-1" {
		t.Errorf("expected key id stamped, got %q", b.KeyID)
	}
	ok, reason := Verify(b, key)
	if !ok || reason != "verified" {
		t.Fatalf("fresh bundle should verify, got (%v, %s)", ok, reason)
	}
}

func TestTamperedFieldFailsSignature(t *testing.T) {
	b := Build("acme", "session-123", sampleEntries(), time.Unix(1000, 0))
	if err := Sign(&b, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	// An auditor's adversary rewrites a reason after signing.
	b.Entries[0].Reason = "allow"
	if ok, reason := Verify(b, key); ok || reason != "signature_mismatch" {
		t.Fatalf("tampered reason should fail signature, got (%v, %s)", ok, reason)
	}
}

func TestWrongKeyFails(t *testing.T) {
	b := Build("acme", "s", sampleEntries(), time.Unix(1000, 0))
	if err := Sign(&b, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(b, []byte("a-different-key-................")); ok {
		t.Fatal("verification with the wrong key should fail")
	}
}

func TestBrokenChainLinkageFails(t *testing.T) {
	e := sampleEntries()
	e[1].PrevHash = "not-h1" // splice: entry 2 no longer follows entry 1
	b := Build("acme", "s", e, time.Unix(1000, 0))
	if err := Sign(&b, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	// Signature still matches (we signed the spliced bundle), but the internal
	// linkage check must catch the break.
	if ok, reason := Verify(b, key); ok || reason != "chain_break" {
		t.Fatalf("spliced chain should fail linkage, got (%v, %s)", ok, reason)
	}
}

func TestUnsignedFails(t *testing.T) {
	b := Build("acme", "s", sampleEntries(), time.Unix(1000, 0))
	if ok, reason := Verify(b, key); ok || reason != "unsigned" {
		t.Fatalf("unsigned bundle should not verify, got (%v, %s)", ok, reason)
	}
}
