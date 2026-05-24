package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NetGnarus/intentgate-gateway/internal/provenance"
)

// HeaderIntentMemoryProvenance is the HTTP header an SDK-instrumented
// agent sends alongside a tools/call to declare which memory entries
// influenced the call. The value is a base64url-encoded JSON array of
// provenanceWireEntry objects (see below).
//
// Header rather than body field because (a) the SDK already inserts
// X-Intent-Prompt this way and consistency wins, (b) provenance
// metadata logically describes the request rather than the tool
// parameters and shouldn't pollute the params namespace, (c) the body
// is fixed by the JSON-RPC envelope and we don't want to fork it.
const HeaderIntentMemoryProvenance = "X-Intent-Memory-Provenance"

// provenanceWireEntry is the wire-format shape of one memory-entry
// reference in the header. Mirrors the fields of provenance.Envelope
// minus the obvious ID (each map key is the entry's ID).
//
// All byte-typed fields are base64url-encoded on the wire because
// HTTP headers are 7-bit ASCII and binary in headers is asking for
// trouble. PrevHash and HMAC are decoded to []byte on receive.
type provenanceWireEntry struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Timestamp int64  `json:"ts"`
	Data      string `json:"data"`      // base64url
	PrevHash  string `json:"prev_hash"` // base64url
	HMAC      string `json:"hmac"`      // base64url
}

// provenanceCheckResult bundles what the provenance stage learned.
type provenanceCheckResult struct {
	// summary is a short tag used by logs and metrics labels.
	// Values: "skipped" (feature off), "no_header" (feature on, no
	// header sent — tenant policy decides whether that's allowed),
	// "verified" (chain verified successfully, N entries), "denied"
	// (verification failed — err is non-nil).
	summary string
	// entryCount is the number of memory entries the agent declared
	// influenced this call (0 when header absent).
	entryCount int
	// err is non-nil when the check FAILED (a real attacker signal),
	// distinct from "no header sent." The handler turns a non-nil err
	// into a CodeProvenanceFailed JSON-RPC error.
	err error
	// errKind is the structured failure reason (ErrKindSignature,
	// ErrKindChain, ErrKindMalformed, ErrKindConfig). Lifted from the
	// provenance.Error so the audit emitter can put it in a
	// structured field without parsing the message string.
	errKind provenance.ErrKind
}

// runProvenanceCheck is check 3 in the pipeline (between intent and
// policy). It only does meaningful work when:
//
//  1. The handler has ProvenanceEnabled == true on its config
//     (operator opted in via INTENTGATE_PROVENANCE_ENABLED), AND
//  2. The verified capability token's master key is non-nil (we have
//     something to derive session keys from), AND
//  3. The request carries an X-Intent-Memory-Provenance header.
//
// When any of the three is false the check returns a "skipped" or
// "no_header" result. The tenant policy author can then decide
// (via OPA, downstream) whether absence of provenance is itself a
// deny condition for a given tool.
func (h *mcpHandler) runProvenanceCheck(
	ctx context.Context,
	headerValue string,
	capJTI string,
) provenanceCheckResult {
	if !h.cfg.ProvenanceEnabled {
		return provenanceCheckResult{summary: "skipped"}
	}
	if len(h.cfg.MasterKey) == 0 {
		// Misconfiguration: provenance enabled but no master key to
		// derive from. Skip with a logged warning rather than fail
		// closed — the handler's startup wiring should have caught
		// this; reaching here means something raced.
		h.cfg.Logger.Warn("provenance enabled but master key missing — check skipped")
		return provenanceCheckResult{summary: "skipped"}
	}
	if headerValue == "" {
		// No provenance declared. Not a failure per se — let policy
		// (check 4) decide whether a tool requires provenance.
		return provenanceCheckResult{summary: "no_header"}
	}
	if capJTI == "" {
		// Provenance header present but the capability had no jti to
		// derive the session key from. This combination only happens
		// in dev mode (RequireCapability=false) when an anonymous
		// caller still sent a provenance header. Treat as a
		// malformed-input error.
		return provenanceCheckResult{
			summary: "denied",
			err:     errors.New("provenance header present but no capability jti to derive session key"),
			errKind: provenance.ErrKindConfig,
		}
	}

	// Decode the header. Two-stage: base64url → JSON array.
	rawJSON, err := base64.RawURLEncoding.DecodeString(headerValue)
	if err != nil {
		return provenanceCheckResult{
			summary: "denied",
			err:     fmt.Errorf("provenance header is not valid base64url: %w", err),
			errKind: provenance.ErrKindMalformed,
		}
	}

	var wire []provenanceWireEntry
	if err := json.Unmarshal(rawJSON, &wire); err != nil {
		return provenanceCheckResult{
			summary: "denied",
			err:     fmt.Errorf("provenance header is not a valid JSON array: %w", err),
			errKind: provenance.ErrKindMalformed,
		}
	}
	if len(wire) == 0 {
		// Empty array — same shape as no header. Pass through.
		return provenanceCheckResult{summary: "no_header"}
	}

	// Convert wire entries to provenance.Envelope. Fail closed on any
	// decoding error — these are short fields with well-known encoding,
	// no recovery is sensible.
	chain := make([]provenance.Envelope, 0, len(wire))
	for i, w := range wire {
		dataBytes, err := base64.RawURLEncoding.DecodeString(w.Data)
		if err != nil {
			return provenanceCheckResult{
				summary: "denied",
				err:     fmt.Errorf("entry %d: data field is not valid base64url: %w", i, err),
				errKind: provenance.ErrKindMalformed,
			}
		}
		prevBytes, err := base64.RawURLEncoding.DecodeString(w.PrevHash)
		if err != nil {
			return provenanceCheckResult{
				summary: "denied",
				err:     fmt.Errorf("entry %d: prev_hash field is not valid base64url: %w", i, err),
				errKind: provenance.ErrKindMalformed,
			}
		}
		hmacBytes, err := base64.RawURLEncoding.DecodeString(w.HMAC)
		if err != nil {
			return provenanceCheckResult{
				summary: "denied",
				err:     fmt.Errorf("entry %d: hmac field is not valid base64url: %w", i, err),
				errKind: provenance.ErrKindMalformed,
			}
		}
		// Cross-check session_id consistency. Every entry in a single
		// provenance header MUST belong to the same session as the
		// capability token presenting them — that's the whole point
		// of binding signatures to the capability jti.
		if w.SessionID != capJTI {
			return provenanceCheckResult{
				summary: "denied",
				err: fmt.Errorf(
					"entry %d: session_id %q does not match capability jti %q",
					i, w.SessionID, capJTI,
				),
				errKind: provenance.ErrKindSignature,
			}
		}
		chain = append(chain, provenance.Envelope{
			ID:        w.ID,
			SessionID: w.SessionID,
			Timestamp: w.Timestamp,
			Data:      dataBytes,
			PrevHash:  prevBytes,
			HMAC:      hmacBytes,
		})
	}

	// Re-derive the session signing key from the master key and the
	// capability's jti. Identical to what the SDK did at write time.
	sessionKey, err := provenance.DeriveSessionKey(h.cfg.MasterKey, capJTI)
	if err != nil {
		return provenanceCheckResult{
			summary: "denied",
			err:     fmt.Errorf("derive session key: %w", err),
			errKind: provenance.ErrKindConfig,
		}
	}

	// Walk the chain. Returns first error encountered with the
	// offending entry index in the message.
	if err := provenance.VerifyChain(sessionKey, chain); err != nil {
		var pErr *provenance.Error
		kind := provenance.ErrKindSignature
		if errors.As(err, &pErr) {
			kind = pErr.Kind
		}
		return provenanceCheckResult{
			summary:    "denied",
			entryCount: len(chain),
			err:        err,
			errKind:    kind,
		}
	}

	return provenanceCheckResult{
		summary:    fmt.Sprintf("verified (%d entries)", len(chain)),
		entryCount: len(chain),
	}
}

// ProvenanceWireEntry is the exported wire-format type the SDK
// reference implementations (and any external client that wants to
// build a provenance header without taking a dep on this package's
// internals) marshal into. It is the same shape as the unexported
// provenanceWireEntry above; we re-export it here so the type
// crosses the package boundary cleanly.
type ProvenanceWireEntry = provenanceWireEntry

// EncodeProvenanceHeader takes a slice of wire entries and returns
// the base64url(json([])) value an SDK puts into the
// X-Intent-Memory-Provenance header. Exposed for SDK
// reference-implementations and for tests.
func EncodeProvenanceHeader(entries []ProvenanceWireEntry) (string, error) {
	if len(entries) == 0 {
		return "", nil
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("marshal provenance entries: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
