// Package provenance implements memory-entry signing and verification
// for IntentGate's AAI03 (Memory Poisoning) defense.
//
// # Overview
//
// Memory provenance closes the sophisticated case of OWASP Agentic AI
// Top 10 AAI03 — where an attacker has write access to the agent's
// memory store and plants entries crafted to align with the user's
// prompt (passing the intent check) while corrupting the resulting
// tool call's arguments in a subtle way.
//
// The defense: each memory entry the agent writes is signed with an
// HMAC. The signing key is per-session, derived (via HKDF) from the
// gateway's master key and the capability token's jti. At tool-call
// time the agent includes the entries that backed the call in a new
// header; the gateway re-derives the session key, verifies the HMAC
// over each entry, and walks the per-session hash chain (prev_hash
// links) to confirm contiguity. Any verification failure → typed
// ProvenanceError, denied at check 3 of the pipeline (between intent
// and policy).
//
// # Design decisions
//
// Pinned in memos/aai03-memory-provenance-design.md §1:
//
//   - Opt-in (off by default; customers enable per-tenant).
//   - Signing key derived from capability-token trust boundary, no
//     separate runtime component.
//   - HMAC-SHA256, not Ed25519 / JWTs / accumulators.
//   - Brand: "intent verification with provenance," not "five-check
//     pipeline." (No effect on this package; documented for context.)
//
// # Why HKDF and not raw HMAC for key derivation
//
// HKDF-SHA256 (RFC 5869) is the standard way to derive a
// cryptographically-independent sub-key from existing key material.
// We use it instead of a direct HMAC(master, jti) construction so we
// can include a versioned `info` label ("intentgate-memory-v1") in the
// derivation. That lets us rotate the derivation function later
// without invalidating in-flight tokens (a future version would accept
// both v1 and v2 derivations during a grace window).
//
// # Wire format
//
// An Envelope is the unit a customer's agent stores in its memory
// backend. It carries the opaque content the agent wrote (Data), the
// session identifier that signed it (SessionID, set to the capability
// token's jti), the in-session chain link (PrevHash), and the HMAC
// over a canonical serialization of all the above. See Canonical for
// the exact byte sequence the HMAC covers.
package provenance

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/hkdf"
)

// SessionKeySize is the byte length of a derived per-session memory
// signing key. Matches HMAC-SHA256's block-rate output range; 32 bytes
// is the size HKDF naturally produces when info is unrestricted.
const SessionKeySize = 32

// derivationInfo is the HKDF `info` label. Includes a version suffix
// so the derivation function can be rotated independently of the
// master key. If we ever change the derivation, we'd accept both v1
// and v2 during a grace window.
const derivationInfo = "intentgate-memory-v1"

// hashSize is the byte length of SHA-256 / HMAC-SHA256 output. Used
// for PrevHash and HMAC fields.
const hashSize = sha256.Size

// zeroHash is the conventional PrevHash value for the first entry in
// a session — the "genesis" link.
var zeroHash = make([]byte, hashSize)

// Envelope is one signed memory entry. The agent's IntentGate SDK
// produces these on write; the customer's memory backend stores them
// as opaque content; the gateway verifies them at tool-call time.
//
// All fields are mandatory except Data (which may be a zero-length
// slice — represents an entry intentionally cleared of content).
type Envelope struct {
	// ID is a stable, monotonic identifier for the entry. Conventionally
	// a ULID assigned at write time. Used by the SDK to retrieve the
	// entry on read and by the gateway as the key in the provenance
	// header.
	ID string

	// SessionID equals the capability token's jti that issued the
	// signing key. Identifies which session-key the gateway must
	// re-derive to verify.
	SessionID string

	// Timestamp is the entry's creation time as a Unix milliseconds
	// integer. Included in the canonical bytes so two envelopes with
	// the same payload but different timestamps produce distinct HMACs.
	Timestamp int64

	// Data is the application-level payload the agent stored. Opaque
	// to the provenance layer; HMAC covers it byte-for-byte.
	Data []byte

	// PrevHash is the SHA-256 hash of the canonical bytes of the
	// previous entry in the same session. ZeroHash (all-zero bytes)
	// for the genesis entry. Forms a per-session hash chain that
	// makes mid-session tampering detectable.
	PrevHash []byte

	// HMAC is the HMAC-SHA256 of Canonical(envelope without HMAC)
	// under the session signing key derived from (masterKey, SessionID).
	HMAC []byte
}

// DeriveSessionKey produces a per-session memory signing key from the
// gateway's master key and the capability token's jti.
//
// Both the agent SDK (signing entries on write) and the gateway
// (verifying on tool-call) call this function with identical inputs
// and receive identical output. The key never travels separately from
// the capability token bundle — re-derivation by both sides is what
// keeps the trust boundary single.
//
// Returns an error only if masterKey is empty or sessionID is empty,
// since HKDF-SHA256 itself is infallible on the input ranges we use.
func DeriveSessionKey(masterKey []byte, sessionID string) ([]byte, error) {
	if len(masterKey) == 0 {
		return nil, errors.New("provenance: master key is empty")
	}
	if sessionID == "" {
		return nil, errors.New("provenance: session id is empty")
	}
	r := hkdf.New(sha256.New, masterKey, []byte(sessionID), []byte(derivationInfo))
	key := make([]byte, SessionKeySize)
	if _, err := r.Read(key); err != nil {
		// HKDF.Read is infallible for outputs within the derivation
		// limit (255 * hashSize bytes); we ask for 32 bytes from a
		// SHA-256 HKDF, so the limit is 8160 bytes. We will never hit
		// this path in normal operation; we still surface the error
		// rather than panic in case the stdlib contract changes.
		return nil, fmt.Errorf("provenance: hkdf read failed: %w", err)
	}
	return key, nil
}

// Canonical produces the byte sequence the envelope's HMAC covers.
//
// The encoding is a length-prefixed concatenation of the immutable
// fields: SessionID, ID, Timestamp, PrevHash, Data. Lengths are
// big-endian uint32 (for the variable-length byte fields) or
// big-endian int64 (for Timestamp). Strings are encoded as their
// UTF-8 bytes; byte slices are written verbatim.
//
// The encoding is deliberately NOT JSON. Two reasons:
//
//  1. Byte-determinism: a length-prefixed wire format gives one and
//     only one canonical encoding for each envelope. JSON has
//     whitespace, key-ordering, and unicode-escape ambiguities that a
//     careful canonicalization can defeat, but a length-prefixed form
//     has none of those classes by construction.
//
//  2. Parser surface: HMAC verification must not depend on a JSON
//     parser at all. A length-prefix encoding can be re-emitted by
//     either side without ever invoking encoding/json, which removes
//     a class of "parser confusion" attacks where the signer and
//     verifier disagree on what the canonical bytes were.
//
// The HMAC field is excluded (you can't sign your own signature).
func Canonical(e Envelope) []byte {
	// Capacity estimate: 4*4 length prefixes + 8 timestamp +
	// SessionID + ID + PrevHash + Data, with a small slack.
	out := make([]byte, 0, 32+len(e.SessionID)+len(e.ID)+len(e.PrevHash)+len(e.Data))

	out = appendLenPrefixed(out, []byte(e.SessionID))
	out = appendLenPrefixed(out, []byte(e.ID))

	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.Timestamp))
	out = append(out, ts[:]...)

	out = appendLenPrefixed(out, e.PrevHash)
	out = appendLenPrefixed(out, e.Data)
	return out
}

// appendLenPrefixed appends a big-endian uint32 length followed by
// the byte slice itself. Used by Canonical.
func appendLenPrefixed(dst, b []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	dst = append(dst, l[:]...)
	dst = append(dst, b...)
	return dst
}

// Sign computes the HMAC for an envelope under sessionKey and returns
// a copy of the envelope with the HMAC field populated.
//
// Sign is used by tests and by the gateway's reference implementation
// of the SDK shim. In production, signing happens client-side in the
// customer's agent process via the SDK — the gateway itself only
// verifies. The function lives in this package so signer and verifier
// share one canonical implementation.
func Sign(sessionKey []byte, e Envelope) (Envelope, error) {
	if len(sessionKey) == 0 {
		return Envelope{}, errors.New("provenance: session key is empty")
	}
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(Canonical(e))
	signed := e
	signed.HMAC = mac.Sum(nil)
	return signed, nil
}

// Verify checks an envelope's HMAC against sessionKey.
//
// Returns nil on a valid signature; a typed Error otherwise.
// Comparison uses hmac.Equal, which is constant-time with respect to
// signature contents — a non-matching HMAC takes the same time as a
// matching one, denying any timing oracle.
func Verify(sessionKey []byte, e Envelope) error {
	if len(sessionKey) == 0 {
		return &Error{Reason: "session key is empty", Kind: ErrKindConfig}
	}
	if len(e.HMAC) != hashSize {
		return &Error{
			Reason: fmt.Sprintf("hmac field is %d bytes; expected %d", len(e.HMAC), hashSize),
			Kind:   ErrKindMalformed,
		}
	}
	mac := hmac.New(sha256.New, sessionKey)
	mac.Write(Canonical(e))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, e.HMAC) {
		return &Error{Reason: "hmac mismatch", Kind: ErrKindSignature}
	}
	return nil
}

// VerifyChain checks a list of envelopes as a per-session chain: each
// entry's HMAC must verify under sessionKey, AND each entry's
// PrevHash must equal SHA-256(Canonical(previous entry)). The first
// entry's PrevHash must equal ZeroHash.
//
// The chain check makes mid-session tampering detectable. An attacker
// who silently substitutes one entry for another (e.g., by replacing
// the row in the customer's memory store) breaks the chain at the
// next valid entry the agent presents — even if both entries are
// individually well-formed.
//
// Returns the first error encountered, walking left to right. The
// error message includes the index of the offending entry.
func VerifyChain(sessionKey []byte, chain []Envelope) error {
	if len(chain) == 0 {
		return nil
	}
	for i, e := range chain {
		if err := Verify(sessionKey, e); err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		var expectedPrev []byte
		if i == 0 {
			expectedPrev = zeroHash
		} else {
			h := sha256.Sum256(Canonical(chain[i-1]))
			expectedPrev = h[:]
		}
		if !hmac.Equal(expectedPrev, e.PrevHash) {
			return &Error{
				Reason: fmt.Sprintf("entry %d: prev_hash does not match previous entry's canonical hash", i),
				Kind:   ErrKindChain,
			}
		}
	}
	return nil
}

// ZeroHash returns the conventional "no previous entry" value used as
// the PrevHash of a session's first envelope. Callers in tests and in
// the SDK use this rather than constructing the zero slice inline so
// the special-case value is named.
func ZeroHash() []byte {
	out := make([]byte, hashSize)
	copy(out, zeroHash)
	return out
}

// EncodeHMAC returns the URL-safe base64 (no padding) encoding of an
// envelope's HMAC. Used when the SDK packs the HMAC into the
// X-Intent-Memory-Provenance header for over-the-wire transport.
func EncodeHMAC(e Envelope) string {
	return base64.RawURLEncoding.EncodeToString(e.HMAC)
}

// ErrKind discriminates the reason a verification failed. Carried on
// Error so callers (the MCP handler, the audit emitter) can map it to
// a structured field in the audit log without re-parsing the message.
type ErrKind int

const (
	// ErrKindConfig indicates the gateway itself is misconfigured —
	// e.g., the session key derivation failed because the master key
	// is missing. NOT an attacker-controlled failure mode.
	ErrKindConfig ErrKind = iota
	// ErrKindMalformed indicates the envelope is structurally invalid
	// (wrong-sized HMAC field, etc.). Could be an attack (truncated
	// payload) or a buggy SDK; we audit but don't distinguish.
	ErrKindMalformed
	// ErrKindSignature indicates the HMAC over the envelope does not
	// verify under the session key. The most common "real attack"
	// failure mode.
	ErrKindSignature
	// ErrKindChain indicates a prev_hash mismatch — an entry whose
	// stated predecessor is not what's actually presented. Catches
	// mid-session tampering.
	ErrKindChain
)

// Error is the typed error returned by Verify and VerifyChain.
// Carries both the human-readable reason and a structured Kind for
// audit log emission.
type Error struct {
	Reason string
	Kind   ErrKind
}

func (e *Error) Error() string { return "provenance: " + e.Reason }
