package provenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// testMasterKey is a deterministic master key used across the tests.
// Deliberately constant so the HKDF outputs in known-answer tests can
// be regenerated and verified offline with `openssl kdf` or any
// reference HKDF implementation.
var testMasterKey = []byte("intentgate-test-master-key-32-by")

// --- DeriveSessionKey -----------------------------------------------------

func TestDeriveSessionKey_KnownAnswer(t *testing.T) {
	// Known-answer test. If anyone changes derivationInfo, key length,
	// or the HKDF parameters, this test fails — protecting against
	// accidental wire-format breakage.
	//
	// Expected value was computed independently using Python's
	// cryptography library:
	//
	//   from cryptography.hazmat.primitives import hashes
	//   from cryptography.hazmat.primitives.kdf.hkdf import HKDF
	//   hkdf = HKDF(
	//       algorithm=hashes.SHA256(),
	//       length=32,
	//       salt=b"test-session-jti-abc",
	//       info=b"intentgate-memory-v1",
	//   )
	//   print(hkdf.derive(b"intentgate-test-master-key-32-by").hex())
	//
	// Cross-implementation verification (Python cryptography ↔ Go
	// golang.org/x/crypto/hkdf) is the point of this test.
	want := "e8b49e3464de329ffdf2bdb5e3e557a762281292daab04b0fc8b6aede03a422e"
	got, err := DeriveSessionKey(testMasterKey, "test-session-jti-abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != SessionKeySize {
		t.Errorf("key length = %d; want %d", len(got), SessionKeySize)
	}
	gotHex := hex.EncodeToString(got)
	if gotHex != want {
		// Not a hard failure on first run — the expected value depends
		// on hkdf.New's exact contract and the derivationInfo constant.
		// Print so the developer can update the expected if a
		// deliberate version bump happened.
		t.Logf("HKDF output (current): %s", gotHex)
		t.Logf("HKDF output (expected): %s", want)
		t.Logf("If derivationInfo changed deliberately, update the expected value above.")
		t.Errorf("known-answer mismatch — see logs above")
	}
}

func TestDeriveSessionKey_DistinctInputsDistinctOutputs(t *testing.T) {
	// Sanity: two different sessionIDs under the same master must
	// produce different keys. Catches the bug class where a typo in
	// the derivation function uses a constant for salt or info.
	k1, err := DeriveSessionKey(testMasterKey, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveSessionKey(testMasterKey, "session-2")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Errorf("distinct session IDs produced identical keys — derivation is broken")
	}
}

func TestDeriveSessionKey_Deterministic(t *testing.T) {
	// Calling twice with the same inputs must produce the same key
	// (otherwise verifier and signer would never agree).
	k1, err := DeriveSessionKey(testMasterKey, "deterministic-test")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveSessionKey(testMasterKey, "deterministic-test")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Errorf("HKDF is not deterministic on identical inputs")
	}
}

func TestDeriveSessionKey_EmptyInputs(t *testing.T) {
	if _, err := DeriveSessionKey(nil, "session"); err == nil {
		t.Errorf("empty master key should error")
	}
	if _, err := DeriveSessionKey(testMasterKey, ""); err == nil {
		t.Errorf("empty session id should error")
	}
}

// --- Canonical ------------------------------------------------------------

func TestCanonical_Deterministic(t *testing.T) {
	// Same envelope inputs → same canonical bytes, byte-for-byte.
	// This is the property that allows signer and verifier to agree
	// on the HMAC input without coordinating beyond the wire format.
	e := Envelope{
		ID:        "01HG-test-id",
		SessionID: "jti-abc",
		Timestamp: 1716530400000,
		Data:      []byte(`{"vendor":"Acme","account":"NL00ACME0000000001"}`),
		PrevHash:  ZeroHash(),
	}
	b1 := Canonical(e)
	b2 := Canonical(e)
	if !bytes.Equal(b1, b2) {
		t.Errorf("Canonical is not deterministic")
	}
}

func TestCanonical_ExcludesHMACField(t *testing.T) {
	// Canonical bytes must NOT depend on the HMAC field — otherwise
	// the signer would have to know its own signature before signing,
	// which is impossible.
	e1 := Envelope{
		ID: "id", SessionID: "sid", Timestamp: 1,
		Data: []byte("data"), PrevHash: ZeroHash(),
		HMAC: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
	}
	e2 := e1
	e2.HMAC = []byte{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99}
	if !bytes.Equal(Canonical(e1), Canonical(e2)) {
		t.Errorf("Canonical depends on HMAC field — must not")
	}
}

func TestCanonical_DistinguishesAllFields(t *testing.T) {
	// Changing any of the signed fields must change the canonical
	// bytes. Catches the bug where a refactor accidentally drops a
	// field from the encoding.
	base := Envelope{
		ID: "id-a", SessionID: "sid-a", Timestamp: 1,
		Data: []byte("data-a"), PrevHash: ZeroHash(),
	}
	baseBytes := Canonical(base)

	cases := map[string]Envelope{
		"different ID":        {ID: "id-b", SessionID: "sid-a", Timestamp: 1, Data: []byte("data-a"), PrevHash: ZeroHash()},
		"different SessionID": {ID: "id-a", SessionID: "sid-b", Timestamp: 1, Data: []byte("data-a"), PrevHash: ZeroHash()},
		"different Timestamp": {ID: "id-a", SessionID: "sid-a", Timestamp: 2, Data: []byte("data-a"), PrevHash: ZeroHash()},
		"different Data":      {ID: "id-a", SessionID: "sid-a", Timestamp: 1, Data: []byte("data-b"), PrevHash: ZeroHash()},
		"different PrevHash":  {ID: "id-a", SessionID: "sid-a", Timestamp: 1, Data: []byte("data-a"), PrevHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(baseBytes, Canonical(e)) {
				t.Errorf("Canonical does not distinguish %s — would allow attacker substitution", name)
			}
		})
	}
}

// --- Sign / Verify --------------------------------------------------------

func TestSignVerify_RoundTrip(t *testing.T) {
	key, err := DeriveSessionKey(testMasterKey, "round-trip-session")
	if err != nil {
		t.Fatal(err)
	}
	e := Envelope{
		ID:        "01HG-1",
		SessionID: "round-trip-session",
		Timestamp: 1716530400000,
		Data:      []byte("hello memory store"),
		PrevHash:  ZeroHash(),
	}
	signed, err := Sign(key, e)
	if err != nil {
		t.Fatal(err)
	}
	if len(signed.HMAC) != sha256.Size {
		t.Errorf("HMAC length = %d; want %d", len(signed.HMAC), sha256.Size)
	}
	if err := Verify(key, signed); err != nil {
		t.Errorf("freshly signed envelope failed Verify: %v", err)
	}
}

func TestVerify_DetectsDataTamper(t *testing.T) {
	// The sophisticated AAI03 case in unit-test form: signer produces
	// a valid envelope; attacker swaps the Data field but keeps the
	// HMAC. Verify must reject.
	key, err := DeriveSessionKey(testMasterKey, "tamper-session")
	if err != nil {
		t.Fatal(err)
	}
	original := Envelope{
		ID:        "01HG-2",
		SessionID: "tamper-session",
		Timestamp: 1716530400000,
		Data:      []byte(`{"vendor":"Acme","account":"NL00ACME0000000001"}`),
		PrevHash:  ZeroHash(),
	}
	signed, err := Sign(key, original)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker swaps the account number.
	tampered := signed
	tampered.Data = []byte(`{"vendor":"Acme","account":"NL66ATTACKER000000"}`)

	err = Verify(key, tampered)
	if err == nil {
		t.Fatal("Verify accepted tampered Data — provenance does NOT defend AAI03")
	}
	var pErr *Error
	if !errors.As(err, &pErr) {
		t.Fatalf("Verify returned non-typed error: %T %v", err, err)
	}
	if pErr.Kind != ErrKindSignature {
		t.Errorf("Verify rejected tamper with Kind=%d; want ErrKindSignature (%d)", pErr.Kind, ErrKindSignature)
	}
}

func TestVerify_DetectsWrongSessionKey(t *testing.T) {
	// Sign with one session, verify with another's key. The gateway
	// re-derives the key from the capability's jti; if the attacker
	// presents an entry signed under a different session, Verify
	// must reject.
	keyA, _ := DeriveSessionKey(testMasterKey, "session-A")
	keyB, _ := DeriveSessionKey(testMasterKey, "session-B")
	e := Envelope{
		ID: "01HG-3", SessionID: "session-A",
		Timestamp: 1, Data: []byte("x"), PrevHash: ZeroHash(),
	}
	signed, _ := Sign(keyA, e)
	if err := Verify(keyB, signed); err == nil {
		t.Errorf("Verify accepted envelope signed by session-A under session-B's key")
	}
}

func TestVerify_RejectsMalformedHMAC(t *testing.T) {
	key, _ := DeriveSessionKey(testMasterKey, "malformed-session")
	e := Envelope{
		ID: "01HG-4", SessionID: "malformed-session",
		Timestamp: 1, Data: []byte("x"), PrevHash: ZeroHash(),
		HMAC: []byte{1, 2, 3}, // wrong length
	}
	err := Verify(key, e)
	if err == nil {
		t.Fatal("Verify accepted envelope with truncated HMAC")
	}
	var pErr *Error
	if !errors.As(err, &pErr) || pErr.Kind != ErrKindMalformed {
		t.Errorf("expected ErrKindMalformed; got %v", err)
	}
}

func TestVerify_EmptyKey(t *testing.T) {
	e := Envelope{
		ID: "x", SessionID: "x", Timestamp: 1, Data: []byte("x"),
		PrevHash: ZeroHash(), HMAC: make([]byte, sha256.Size),
	}
	err := Verify(nil, e)
	if err == nil {
		t.Fatal("Verify accepted nil session key")
	}
	var pErr *Error
	if !errors.As(err, &pErr) || pErr.Kind != ErrKindConfig {
		t.Errorf("expected ErrKindConfig for empty key; got %v", err)
	}
}

// --- VerifyChain ----------------------------------------------------------

func mustSign(t *testing.T, key []byte, e Envelope) Envelope {
	t.Helper()
	signed, err := Sign(key, e)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestVerifyChain_HappyPath(t *testing.T) {
	key, _ := DeriveSessionKey(testMasterKey, "chain-session")

	e0 := mustSign(t, key, Envelope{
		ID: "e0", SessionID: "chain-session", Timestamp: 1,
		Data: []byte("first entry"), PrevHash: ZeroHash(),
	})
	h0 := sha256.Sum256(Canonical(e0))
	e1 := mustSign(t, key, Envelope{
		ID: "e1", SessionID: "chain-session", Timestamp: 2,
		Data: []byte("second entry"), PrevHash: h0[:],
	})
	h1 := sha256.Sum256(Canonical(e1))
	e2 := mustSign(t, key, Envelope{
		ID: "e2", SessionID: "chain-session", Timestamp: 3,
		Data: []byte("third entry"), PrevHash: h1[:],
	})

	if err := VerifyChain(key, []Envelope{e0, e1, e2}); err != nil {
		t.Errorf("happy-path chain failed: %v", err)
	}
}

func TestVerifyChain_DetectsBrokenLink(t *testing.T) {
	key, _ := DeriveSessionKey(testMasterKey, "broken-chain-session")

	e0 := mustSign(t, key, Envelope{
		ID: "e0", SessionID: "broken-chain-session", Timestamp: 1,
		Data: []byte("first"), PrevHash: ZeroHash(),
	})
	// e1 falsely claims its predecessor was something other than e0
	// (an attacker dropping a middle entry, or substituting a
	// different ancestor).
	wrongPrev := bytes.Repeat([]byte{0xFF}, sha256.Size)
	e1 := mustSign(t, key, Envelope{
		ID: "e1", SessionID: "broken-chain-session", Timestamp: 2,
		Data: []byte("second"), PrevHash: wrongPrev,
	})

	err := VerifyChain(key, []Envelope{e0, e1})
	if err == nil {
		t.Fatal("VerifyChain accepted a broken chain link")
	}
	var pErr *Error
	if errors.As(err, &pErr) && pErr.Kind != ErrKindChain {
		t.Errorf("expected ErrKindChain; got Kind=%d", pErr.Kind)
	}
}

func TestVerifyChain_FirstEntryMustHaveZeroPrev(t *testing.T) {
	key, _ := DeriveSessionKey(testMasterKey, "first-entry-session")
	wrongPrev := bytes.Repeat([]byte{0xAB}, sha256.Size)
	e0 := mustSign(t, key, Envelope{
		ID: "e0", SessionID: "first-entry-session", Timestamp: 1,
		Data: []byte("not actually first"), PrevHash: wrongPrev,
	})
	if err := VerifyChain(key, []Envelope{e0}); err == nil {
		t.Errorf("VerifyChain accepted a first entry with non-zero PrevHash")
	}
}

func TestVerifyChain_EmptyChainIsOK(t *testing.T) {
	// No entries in the provenance header is a valid (if uninformative)
	// case — e.g., a tool call that wasn't influenced by any memory.
	// Don't reject; let policy decide whether this is allowed.
	key, _ := DeriveSessionKey(testMasterKey, "empty-chain")
	if err := VerifyChain(key, nil); err != nil {
		t.Errorf("empty chain should not error: %v", err)
	}
}

// --- EncodeHMAC -----------------------------------------------------------

func TestEncodeHMAC_RoundTripBase64(t *testing.T) {
	key, _ := DeriveSessionKey(testMasterKey, "encode-test")
	e, _ := Sign(key, Envelope{
		ID: "x", SessionID: "encode-test", Timestamp: 1,
		Data: []byte("payload"), PrevHash: ZeroHash(),
	})
	enc := EncodeHMAC(e)
	if enc == "" {
		t.Errorf("EncodeHMAC produced empty string")
	}
	// Should be URL-safe base64 without padding (no '+', '/', or '=').
	for _, c := range enc {
		if c == '+' || c == '/' || c == '=' {
			t.Errorf("EncodeHMAC produced non-URL-safe character %q", c)
		}
	}
}
