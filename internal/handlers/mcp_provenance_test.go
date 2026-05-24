package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/NetGnarus/intentgate-gateway/internal/provenance"
)

// testMaster is the master key used across handler-stage provenance
// tests. Deliberately constant so the derived session keys are
// reproducible.
var testMaster = []byte("intentgate-handler-master-key-32")

// newProvenanceHandler returns a handler with the minimal config
// needed to exercise runProvenanceCheck in isolation. Only the
// fields the stage reads are populated; everything else is left zero.
func newProvenanceHandler(enabled bool) *mcpHandler {
	return &mcpHandler{cfg: MCPHandlerConfig{
		Logger:            slog.Default(),
		MasterKey:         testMaster,
		ProvenanceEnabled: enabled,
	}}
}

// helper: sign an envelope under the per-session derived key.
func signEnvelope(t *testing.T, sessionID string, e provenance.Envelope) provenance.Envelope {
	t.Helper()
	key, err := provenance.DeriveSessionKey(testMaster, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := provenance.Sign(key, e)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// helper: convert a signed Envelope to the wire-format struct the
// handler parses out of the X-Intent-Memory-Provenance header.
func toWire(e provenance.Envelope) provenanceWireEntry {
	return provenanceWireEntry{
		ID:        e.ID,
		SessionID: e.SessionID,
		Timestamp: e.Timestamp,
		Data:      base64.RawURLEncoding.EncodeToString(e.Data),
		PrevHash:  base64.RawURLEncoding.EncodeToString(e.PrevHash),
		HMAC:      base64.RawURLEncoding.EncodeToString(e.HMAC),
	}
}

// helper: build a base64url-encoded provenance header payload from
// a list of wire entries.
func encodeHeader(t *testing.T, entries []provenanceWireEntry) string {
	t.Helper()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// ---------------------------------------------------------------------------
// Skip / no-op paths
// ---------------------------------------------------------------------------

func TestProvenance_Disabled_IsNoOp(t *testing.T) {
	// ProvenanceEnabled=false → header is ignored even when present
	// and looks valid. Used to confirm that turning the feature off
	// truly returns the pre-feature behavior.
	h := newProvenanceHandler(false)
	r := h.runProvenanceCheck(context.Background(), "any-header-value", "any-jti")
	if r.err != nil {
		t.Errorf("disabled check returned error: %v", r.err)
	}
	if r.summary != "skipped" {
		t.Errorf("summary=%q want %q", r.summary, "skipped")
	}
}

func TestProvenance_EnabledNoHeader_IsPassthrough(t *testing.T) {
	// ProvenanceEnabled=true but the request didn't carry a header.
	// Not a failure — let policy decide whether absence of provenance
	// is a deny condition for the specific tool.
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(context.Background(), "", "jti-x")
	if r.err != nil {
		t.Errorf("missing header treated as error: %v", r.err)
	}
	if r.summary != "no_header" {
		t.Errorf("summary=%q want %q", r.summary, "no_header")
	}
}

func TestProvenance_EnabledEmptyArrayHeader_IsPassthrough(t *testing.T) {
	// Header present but contains the empty array. Logically same as
	// "no header" — agent ran without consulting memory.
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(context.Background(), encodeHeader(t, nil), "jti-x")
	if r.err != nil {
		t.Errorf("empty-array header treated as error: %v", r.err)
	}
	if r.summary != "no_header" {
		t.Errorf("summary=%q want %q", r.summary, "no_header")
	}
}

func TestProvenance_EnabledNoMasterKey_SkipsWithWarning(t *testing.T) {
	// Misconfiguration: provenance turned on but the gateway has no
	// master key (only possible in dev mode). Skip rather than
	// fail-closed so the rest of the pipeline keeps running.
	h := &mcpHandler{cfg: MCPHandlerConfig{
		Logger:            slog.Default(),
		MasterKey:         nil,
		ProvenanceEnabled: true,
	}}
	r := h.runProvenanceCheck(context.Background(), "anything", "jti-x")
	if r.err != nil {
		t.Errorf("missing master key produced error: %v", r.err)
	}
	if r.summary != "skipped" {
		t.Errorf("summary=%q want %q", r.summary, "skipped")
	}
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

func TestProvenance_SingleEntry_HappyPath(t *testing.T) {
	const sessionID = "jti-happy-single"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data:     []byte(`{"vendor":"Acme","account":"NL00ACME0000"}`),
		PrevHash: provenance.ZeroHash(),
	})

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(signed)}),
		sessionID,
	)
	if r.err != nil {
		t.Fatalf("happy path failed: %v", r.err)
	}
	if r.entryCount != 1 {
		t.Errorf("entryCount=%d want 1", r.entryCount)
	}
	if !strings.HasPrefix(r.summary, "verified") {
		t.Errorf("summary=%q want \"verified ...\"", r.summary)
	}
}

func TestProvenance_MultiEntryChain_HappyPath(t *testing.T) {
	const sessionID = "jti-happy-chain"
	e0 := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("first"), PrevHash: provenance.ZeroHash(),
	})
	h0 := sha256.Sum256(provenance.Canonical(e0))
	e1 := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e1", SessionID: sessionID, Timestamp: 2,
		Data: []byte("second"), PrevHash: h0[:],
	})

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(e0), toWire(e1)}),
		sessionID,
	)
	if r.err != nil {
		t.Fatalf("chain happy path failed: %v", r.err)
	}
	if r.entryCount != 2 {
		t.Errorf("entryCount=%d want 2", r.entryCount)
	}
}

// ---------------------------------------------------------------------------
// Attack paths — these are the AAI03 sophisticated cases the check
// is supposed to defend against. Each test simulates a real attack
// scenario and asserts the gateway rejects with the right error kind.
// ---------------------------------------------------------------------------

func TestProvenance_DataTampered_Rejected(t *testing.T) {
	// The textbook sophisticated AAI03: signer produces a valid
	// envelope; attacker swaps the data field but keeps the HMAC.
	// VerifyChain catches the mismatch.
	const sessionID = "jti-tampered"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data:     []byte(`{"vendor":"Acme","account":"NL00ACME0000000001"}`),
		PrevHash: provenance.ZeroHash(),
	})

	// Attacker swaps the account number; keeps the rest including HMAC.
	tampered := signed
	tampered.Data = []byte(`{"vendor":"Acme","account":"NL66ATTACKER000000"}`)

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(tampered)}),
		sessionID,
	)
	if r.err == nil {
		t.Fatal("tampered data was accepted — AAI03 sophisticated case NOT defended")
	}
	if r.errKind != provenance.ErrKindSignature {
		t.Errorf("errKind=%v want ErrKindSignature", r.errKind)
	}
}

func TestProvenance_WrongSession_Rejected(t *testing.T) {
	// Agent presents an entry signed under session A but the
	// capability token's jti is session B. The gateway derives the
	// session key from jti=B; the HMAC doesn't verify under B.
	signed := signEnvelope(t, "jti-session-A", provenance.Envelope{
		ID: "e0", SessionID: "jti-session-A", Timestamp: 1,
		Data: []byte("payload"), PrevHash: provenance.ZeroHash(),
	})
	// Lie about the session_id in the wire entry to dodge the
	// pre-derivation consistency check, exposing the HMAC verify.
	wire := toWire(signed)
	wire.SessionID = "jti-session-B"

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{wire}),
		"jti-session-B",
	)
	if r.err == nil {
		t.Fatal("cross-session entry was accepted")
	}
}

func TestProvenance_SessionIDMismatch_Rejected(t *testing.T) {
	// Agent presents an entry whose session_id field doesn't match
	// the capability token's jti. Caught BEFORE the HMAC verify by
	// the early consistency check.
	const sessionID = "jti-session-A"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("payload"), PrevHash: provenance.ZeroHash(),
	})

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(signed)}),
		"jti-session-B", // capability presents B; entry says A
	)
	if r.err == nil {
		t.Fatal("session_id mismatch was accepted")
	}
	if !strings.Contains(r.err.Error(), "session_id") {
		t.Errorf("error message should mention session_id; got %q", r.err.Error())
	}
}

func TestProvenance_BrokenChain_Rejected(t *testing.T) {
	// Two entries that individually verify, but the second one's
	// prev_hash doesn't actually match the first one's canonical
	// hash. Simulates a dropped or substituted middle entry.
	const sessionID = "jti-broken-chain"
	e0 := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("first"), PrevHash: provenance.ZeroHash(),
	})
	// Fabricate a wrong prev_hash for e1.
	wrongPrev := make([]byte, 32)
	for i := range wrongPrev {
		wrongPrev[i] = 0xAB
	}
	e1 := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e1", SessionID: sessionID, Timestamp: 2,
		Data: []byte("second"), PrevHash: wrongPrev,
	})

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(e0), toWire(e1)}),
		sessionID,
	)
	if r.err == nil {
		t.Fatal("broken chain was accepted")
	}
	if r.errKind != provenance.ErrKindChain {
		t.Errorf("errKind=%v want ErrKindChain", r.errKind)
	}
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

func TestProvenance_HeaderNotBase64_Rejected(t *testing.T) {
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(context.Background(), "this is not base64url at all !!!", "jti-x")
	if r.err == nil {
		t.Fatal("malformed base64 header was accepted")
	}
	if r.errKind != provenance.ErrKindMalformed {
		t.Errorf("errKind=%v want ErrKindMalformed", r.errKind)
	}
}

func TestProvenance_HeaderNotJSON_Rejected(t *testing.T) {
	// Valid base64url, but the decoded bytes aren't a JSON array.
	bogus := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(context.Background(), bogus, "jti-x")
	if r.err == nil {
		t.Fatal("non-JSON header was accepted")
	}
	if r.errKind != provenance.ErrKindMalformed {
		t.Errorf("errKind=%v want ErrKindMalformed", r.errKind)
	}
}

func TestProvenance_NoCapabilityJTI_Rejected(t *testing.T) {
	// Header present but no capability token (RequireCapability=false
	// dev mode). Treat as malformed input — can't derive a session
	// key without a jti.
	const sessionID = "jti-x"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("payload"), PrevHash: provenance.ZeroHash(),
	})
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(signed)}),
		"", // no jti
	)
	if r.err == nil {
		t.Fatal("missing capability jti was accepted")
	}
	if r.errKind != provenance.ErrKindConfig {
		t.Errorf("errKind=%v want ErrKindConfig", r.errKind)
	}
}

// ---------------------------------------------------------------------------
// EncodeProvenanceHeader round-trip
// ---------------------------------------------------------------------------

func TestEncodeProvenanceHeader_RoundTrip(t *testing.T) {
	// SDK reference round-trip: encode produces a header value that
	// decodes back through the handler stage. Proves the SDK and
	// handler agree on the wire format.
	const sessionID = "jti-encode"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("encode-roundtrip"), PrevHash: provenance.ZeroHash(),
	})
	header, err := EncodeProvenanceHeader([]ProvenanceWireEntry{toWire(signed)})
	if err != nil {
		t.Fatalf("EncodeProvenanceHeader: %v", err)
	}
	if header == "" {
		t.Fatalf("EncodeProvenanceHeader returned empty string for non-empty input")
	}
	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(context.Background(), header, sessionID)
	if r.err != nil {
		t.Fatalf("encoded header failed to verify: %v", r.err)
	}
}

func TestEncodeProvenanceHeader_EmptyInput(t *testing.T) {
	header, err := EncodeProvenanceHeader(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if header != "" {
		t.Errorf("expected empty string for empty input; got %q", header)
	}
}

// ---------------------------------------------------------------------------
// Sanity: error returned is the typed provenance.Error so the handler
// can extract the Kind for audit emission.
// ---------------------------------------------------------------------------

func TestProvenance_ErrorIsTyped(t *testing.T) {
	const sessionID = "jti-typed-err"
	signed := signEnvelope(t, sessionID, provenance.Envelope{
		ID: "e0", SessionID: sessionID, Timestamp: 1,
		Data: []byte("original"), PrevHash: provenance.ZeroHash(),
	})
	tampered := signed
	tampered.Data = []byte("tampered")

	h := newProvenanceHandler(true)
	r := h.runProvenanceCheck(
		context.Background(),
		encodeHeader(t, []provenanceWireEntry{toWire(tampered)}),
		sessionID,
	)
	if r.err == nil {
		t.Fatal("expected error")
	}
	var pErr *provenance.Error
	if !errors.As(r.err, &pErr) {
		t.Errorf("returned error is not *provenance.Error: %T", r.err)
	}
}
