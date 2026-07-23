package sessionrewind

import (
	"strings"
	"testing"
	"time"
)

func sampleSteps() []Step {
	return []Step{
		{EventID: "e1", Ts: "t1", Tool: "read_ticket", Decision: DecisionAllow},
		{EventID: "e2", Ts: "t2", Tool: "read_customer", Decision: DecisionAllow},
		{EventID: "e3", Ts: "t3", Tool: "escalate_case", Decision: DecisionEscalate},
		{EventID: "e4", Ts: "t4", Tool: "delete_records", Decision: DecisionBlock},
	}
}

var key = []byte("test-master-key-32-bytes-long!!!")

func TestBuildCheckpointsOnlyAllows(t *testing.T) {
	cps := BuildCheckpoints(sampleSteps())
	if len(cps) != 2 {
		t.Fatalf("expected 2 checkpoints (the two allows), got %d", len(cps))
	}
	if cps[0].EventID != "e1" || cps[1].EventID != "e2" {
		t.Errorf("checkpoints out of order or wrong: %+v", cps)
	}
	if cps[0].Hash == cps[1].Hash {
		t.Error("checkpoint hashes should chain and differ")
	}
}

func TestLastSafe(t *testing.T) {
	last, ok := LastSafe(BuildCheckpoints(sampleSteps()))
	if !ok || last.EventID != "e2" {
		t.Fatalf("expected last safe checkpoint e2, got %+v ok=%v", last, ok)
	}
	if _, ok := LastSafe(nil); ok {
		t.Error("no checkpoints should report no safe state")
	}
}

func TestEnvelopeNamesCheckpointAndInoculates(t *testing.T) {
	cps := BuildCheckpoints(sampleSteps())
	last, ok := LastSafe(cps)
	env := BuildEnvelope("sess-1", "delete_records", "scope_violation", last, ok, time.Unix(1000, 0))
	if env.RolledBackTo != last.Hash || env.RolledBackEventID != "e2" {
		t.Errorf("envelope should roll back to the last safe checkpoint, got %+v", env)
	}
	if !strings.Contains(env.SystemNote, "delete_records") || !strings.Contains(env.SystemNote, "scope_violation") {
		t.Errorf("inoculation note should name the tool and reason: %s", env.SystemNote)
	}
	if !strings.Contains(env.SystemNote, "do not retry") {
		t.Errorf("inoculation note should tell the agent not to retry: %s", env.SystemNote)
	}
}

func TestEnvelopeNoSafeCheckpoint(t *testing.T) {
	// A block before any allow: no rollback target, agent restarts from origin.
	steps := []Step{{EventID: "e1", Ts: "t1", Tool: "delete_records", Decision: DecisionBlock}}
	last, ok := LastSafe(BuildCheckpoints(steps))
	env := BuildEnvelope("sess-2", "delete_records", "scope_violation", last, ok, time.Unix(1000, 0))
	if env.RolledBackTo != "" || env.RolledBackEventID != "" {
		t.Errorf("no safe checkpoint should leave rollback target empty, got %+v", env)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	cps := BuildCheckpoints(sampleSteps())
	last, ok := LastSafe(cps)
	env := BuildEnvelope("sess-1", "delete_records", "scope_violation", last, ok, time.Unix(1000, 0))
	if err := Sign(&env, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	if ok, reason := Verify(env, key); !ok || reason != "verified" {
		t.Fatalf("fresh envelope should verify, got (%v, %s)", ok, reason)
	}
}

func TestTamperedEnvelopeFails(t *testing.T) {
	cps := BuildCheckpoints(sampleSteps())
	last, ok := LastSafe(cps)
	env := BuildEnvelope("sess-1", "delete_records", "scope_violation", last, ok, time.Unix(1000, 0))
	if err := Sign(&env, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	// An attacker rewrites the rollback target to skip the correction.
	env.RolledBackTo = "attacker-controlled"
	if ok, reason := Verify(env, key); ok || reason != "signature_mismatch" {
		t.Fatalf("tampered envelope should fail, got (%v, %s)", ok, reason)
	}
}

func TestWrongKeyFails(t *testing.T) {
	cps := BuildCheckpoints(sampleSteps())
	last, ok := LastSafe(cps)
	env := BuildEnvelope("sess-1", "delete_records", "scope_violation", last, ok, time.Unix(1000, 0))
	if err := Sign(&env, "mk-1", key); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Verify(env, []byte("a-different-key-................")); ok {
		t.Fatal("verification with the wrong key should fail")
	}
}
