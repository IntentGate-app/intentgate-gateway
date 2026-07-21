// Package payloads retains what an agent actually received back from a call,
// so an operator can answer "what did this return?" and not only "was it
// allowed?".
//
// It covers both directions. An agent-to-agent invocation reaches the gateway
// as a tool call whose name carries the agent prefix, so the same capture path
// serves agent-to-tool and agent-to-agent without a second mechanism.
//
// # Why this is a separate store
//
// The obvious implementation is a field on the audit event. That would be
// wrong. Audit events are hash-chained and forwarded to whatever SIEMs a
// customer has configured: Splunk, Sentinel, Datadog, S3. Putting response
// bodies on the event does not store them once, it copies them into every one
// of those systems under retention rules the customer set for security
// telemetry, not for customer data. Capture would become an
// undeclared data export.
//
// So responses live here, keyed by the audit event id, with their own
// retention and their own access control. The audit event carries only a hash.
//
// # What is stored
//
// The RAW response is hashed; the REDACTED response is stored. The gateway
// already runs responses through the PII filter and the output-schema guard
// before they reach the agent, and it is that post-filter form which is
// persisted. Redacting at read time would mean the unredacted body existed at
// rest, which is the thing this design is avoiding.
//
// Keeping the hash of the raw form alongside the redacted body is what makes
// the record useful rather than merely indicative: it proves which response
// the agent received, and a mismatch between the two is itself detectable.
//
// # Reading is privileged
//
// A Get is access to customer data and is expected to be gated by role and to
// emit its own audit event. The store does not enforce that (it has no notion
// of an actor) but every caller must: a payload store that anyone with console
// access can browse is a shadow copy of the customer's data with no trail.
package payloads

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// ErrNotFound is returned when no payload exists for an event id, which
// includes the ordinary case of a payload that has passed its expiry.
var ErrNotFound = errors.New("payload not found")

// Record is one captured response.
type Record struct {
	// EventID ties the payload to its audit event. Same value both sides,
	// so a decision and what it returned can always be joined.
	EventID string `json:"event_id"`

	Tenant  string `json:"tenant,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	// Tool is the invoked name. For an agent-to-agent call this carries the
	// agent prefix, so the two directions are distinguishable without a
	// separate field.
	Tool string `json:"tool"`

	// RawSHA256 is the hex digest of the response as it came off the
	// upstream, BEFORE redaction. This is the integrity anchor.
	RawSHA256 string `json:"raw_sha256"`
	// RawBytes is the size of that raw response, retained because it is
	// useful for spotting anomalies and costs nothing in privacy terms.
	RawBytes int `json:"raw_bytes"`

	// Body is the redacted response, exactly as the agent received it.
	Body []byte `json:"body,omitempty"`
	// Redacted records whether the filters changed anything on the way
	// through. False means Body is byte-identical to what was hashed.
	Redacted bool `json:"redacted"`

	CapturedAt time.Time `json:"captured_at"`
	// ExpiresAt is when this row becomes unreadable. Capture is deliberately
	// short-lived: long enough to investigate an incident, not long enough to
	// become a second copy of the customer's database.
	ExpiresAt time.Time `json:"expires_at"`
}

// HashRaw returns the hex SHA-256 of a raw response body. Exported because the
// capture path hashes before redaction, in a different place from where the
// record is assembled.
func HashRaw(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Store persists captured responses.
//
// Implementations must treat expiry as a read-time guarantee, not only a
// cleanup job: a row past ExpiresAt must not be returned even if a sweeper has
// not run yet. Otherwise retention becomes a promise that holds only while a
// background task is healthy.
type Store interface {
	// Put stores a record. Storing the same EventID twice is a no-op rather
	// than an error, so a retried write cannot produce two different bodies
	// for one decision.
	Put(ctx context.Context, rec Record) error

	// Get returns the record for an event id. Returns ErrNotFound when the
	// payload is absent or expired.
	Get(ctx context.Context, tenant, eventID string) (Record, error)

	// Purge deletes expired rows and returns how many went. Safe to call
	// concurrently and on a schedule.
	Purge(ctx context.Context, now time.Time) (int, error)
}
