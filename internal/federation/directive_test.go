package federation

import "testing"

func TestDirectiveSignVerify(t *testing.T) {
	key := []byte("node-signing-key-abcdef0123456789")
	d := Directive{
		Version:  DirectiveVersion,
		NodeID:   "ali-cn-shanghai",
		Stop:     true,
		Scope:    "global",
		Reason:   "incident 4821",
		Seq:      7,
		IssuedAt: "2026-07-24T09:00:00Z",
	}
	if err := SignDirective(&d, DirectiveKeyID, key); err != nil {
		t.Fatal(err)
	}
	if ok, why := VerifyDirective(d, key); !ok {
		t.Fatalf("fresh directive should verify, got %q", why)
	}
	// A flipped stop flag must break the signature: a forged release must fail.
	tampered := d
	tampered.Stop = false
	if ok, _ := VerifyDirective(tampered, key); ok {
		t.Fatal("flipping stop must invalidate the signature")
	}
	// Rebinding to another node must fail (no cross-node replay).
	other := d
	other.NodeID = "aws-us-east-1"
	if ok, _ := VerifyDirective(other, key); ok {
		t.Fatal("changing node id must invalidate the signature")
	}
	// Wrong key must fail.
	if ok, _ := VerifyDirective(d, []byte("the-wrong-key-000000000000000000")); ok {
		t.Fatal("directive must not verify under the wrong key")
	}
}

func TestDirectiveUnsigned(t *testing.T) {
	if ok, why := VerifyDirective(Directive{NodeID: "n"}, []byte("k")); ok || why != "unsigned" {
		t.Errorf("unsigned directive should report unsigned, got ok=%v why=%q", ok, why)
	}
}
