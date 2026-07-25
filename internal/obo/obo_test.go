package obo

import (
	"testing"
	"time"
)

var testKey = []byte("obo-test-key-0123456789abcdef")

func TestMintVerifyRoundTrip(t *testing.T) {
	attrs := map[string]string{"role": "junior_accountant", "dept": "finance", "spend": "5000", "mfa": "true"}
	tok, err := Mint(testKey, "agent-finance-1", "alice@acme", attrs, time.Minute)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	p, err := Verify(testKey, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Subject != "agent-finance-1" {
		t.Errorf("subject = %q", p.Subject)
	}
	if !p.Delegated() || p.OnBehalfOf != "alice@acme" {
		t.Errorf("on-behalf-of = %q, delegated=%v", p.OnBehalfOf, p.Delegated())
	}
	if p.Attr("spend") != "5000" || p.Attr("mfa") != "true" {
		t.Errorf("attrs not preserved: %+v", p.Attrs)
	}
	if p.Attr("missing") != "" {
		t.Errorf("missing attr should be empty")
	}
}

func TestAutonomousHasNoDelegatingUser(t *testing.T) {
	tok, _ := Mint(testKey, "agent-batch-1", "", nil, time.Minute)
	p, err := Verify(testKey, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if p.Delegated() {
		t.Errorf("autonomous token must not be delegated")
	}
}

func TestTamperedPayloadRejected(t *testing.T) {
	tok, _ := Mint(testKey, "agent-x", "alice", map[string]string{"spend": "5000"}, time.Minute)
	// Flip a character in the payload segment.
	b := []byte(tok)
	b[3] ^= 0x01
	if _, err := Verify(testKey, string(b)); err == nil {
		t.Fatal("tampered token verified; want error")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	tok, _ := Mint(testKey, "agent-x", "alice", nil, time.Minute)
	if _, err := Verify([]byte("a-different-key-entirely-000000"), tok); err == nil {
		t.Fatal("token verified under wrong key; want error")
	}
}

func TestExpiredRejected(t *testing.T) {
	// Mint with a tiny positive TTL, then verify after it lapses.
	tok, err := Mint(testKey, "agent-x", "alice", nil, time.Nanosecond)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := Verify(testKey, tok); err == nil {
		t.Fatal("expired token verified; want error")
	}
}

func TestMalformedRejected(t *testing.T) {
	for _, bad := range []string{"", ".", "nodot", "a.", ".b", "!!!.@@@"} {
		if _, err := Verify(testKey, bad); err == nil {
			t.Errorf("malformed %q verified; want error", bad)
		}
	}
}

func TestEmptyKeyRejected(t *testing.T) {
	if _, err := Mint(nil, "a", "b", nil, time.Minute); err == nil {
		t.Error("Mint with empty key should error")
	}
	if _, err := Verify(nil, "x.y"); err == nil {
		t.Error("Verify with empty key should error")
	}
}
