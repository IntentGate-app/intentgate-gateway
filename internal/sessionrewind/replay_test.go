package sessionrewind

import "testing"

func TestFingerprintStableUnderArgOrder(t *testing.T) {
	a := FingerprintArgs("s1", "transfer", map[string]any{"amount": 4500, "to": "acc-1"})
	b := FingerprintArgs("s1", "transfer", map[string]any{"to": "acc-1", "amount": 4500})
	if a != b {
		t.Error("fingerprint must be stable under argument order")
	}
}

func TestFingerprintDiffersByArgsToolSession(t *testing.T) {
	base := FingerprintArgs("s1", "transfer", map[string]any{"amount": 4500})
	if base == FingerprintArgs("s1", "transfer", map[string]any{"amount": 4600}) {
		t.Error("different args should differ")
	}
	if base == FingerprintArgs("s1", "refund", map[string]any{"amount": 4500}) {
		t.Error("different tool should differ")
	}
	if base == FingerprintArgs("s2", "transfer", map[string]any{"amount": 4500}) {
		t.Error("different session should differ")
	}
}

func TestReplayGuardBlocksRepeat(t *testing.T) {
	g := NewReplayGuard()
	fp := FingerprintArgs("s1", "delete_records", map[string]any{"id": 7})

	if g.IsBlocked(fp) {
		t.Fatal("should not be blocked before the first block")
	}
	g.Block(fp)
	if !g.IsBlocked(fp) {
		t.Fatal("identical retry should be short-circuited after a block")
	}
	// A different call in the same session is unaffected.
	other := FingerprintArgs("s1", "delete_records", map[string]any{"id": 8})
	if g.IsBlocked(other) {
		t.Fatal("a different call should not be blocked")
	}
	// Operator re-authorizes.
	g.Clear(fp)
	if g.IsBlocked(fp) {
		t.Fatal("cleared fingerprint should no longer be blocked")
	}
}
