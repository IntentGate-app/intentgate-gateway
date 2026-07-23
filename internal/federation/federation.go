// Package federation implements the DATA-PLANE half of IntentGate's
// split-plane control model: a gateway running inside a customer's own cloud
// boundary rolls its local decision activity up into an aggregate, zero-payload
// telemetry record and pushes it OUTBOUND ONLY to a central control plane.
//
// The golden rule this package exists to enforce is a hard one: policy goes
// down, telemetry goes up, but customer payloads and data NEVER leave the local
// boundary. A Rollup therefore carries only:
//
//   - aggregate decision counts (allow / hold / deny / total) for a time window,
//   - counts broken down by IntentGate's own check names (the gateway's
//     vocabulary, not customer data),
//   - distinct cardinalities (how many agents, tools, sessions were active) as
//     integers only, never the identifiers themselves,
//   - the hash of the local audit chain head, so the control plane can attest
//     tamper-evidence without ever seeing an event, and
//   - an HMAC-SHA256 signature over all of the above.
//
// It deliberately never carries an agent id, a tool name, a reason string, an
// intent summary, an argument, or a result. The Summarize step reduces raw
// events to categorical keys, counts them, and discards the keys; nothing that
// could identify a customer, a record, or a payload survives into the Rollup.
// Residency review (see the accompanying docs) checks exactly this surface.
//
// The signing model mirrors internal/proofofintent: HMAC-SHA256 over the
// canonical JSON with the Signature field cleared, keyed by the gateway master
// key. A control plane that shares the node's rollup key can Verify a rollup
// offline; a rollup altered by one byte fails verification.
package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RollupVersion is the schema version stamped into every rollup. Bump it if the
// signed field set changes, so an old rollup never silently mis-verifies.
const RollupVersion = "fed-rollup-1"

// RollupKeyID is the default signing-key identifier for federation rollups. It
// is distinct from the proof-of-intent key id so a verifier can tell a rollup
// signature apart from a compliance-bundle signature even under the same key.
const RollupKeyID = "federation-rollup-v1"

// DecisionCounts is the aggregate decision breakdown for one window. Counts
// only -- there is no field here that could carry a request or a payload.
type DecisionCounts struct {
	Allow int `json:"allow"` // permitted calls
	Hold  int `json:"hold"`  // escalate: held for a human decision
	Deny  int `json:"deny"`  // block: stopped before the tool was touched
	Total int `json:"total"` // allow + hold + deny (+ any other decision)
}

// Sample is one decision reduced to only the categorical fields that inform an
// aggregate count. The caller maps each local audit event to a Sample; this
// package never sees arguments, reasons, intent text, or results. The Decision
// value uses the gateway's own vocabulary ("allow", "block", "escalate"); Agent
// / Tool / Session are used solely to count DISTINCT values and are then
// discarded -- they never leave this process.
//
// EventID and ResultHash are optional and feed WindowDigest only. Both are
// already opaque -- a random event id and a SHA-256 of the result -- so neither
// is customer data, and neither is ever copied into a Rollup: the residency
// test asserts they never reach the wire.
type Sample struct {
	Decision   string
	Check      string
	Agent      string
	Tool       string
	Session    string
	EventID    string
	ResultHash string
}

// WindowDigest computes a deterministic SHA-256 fingerprint over the ordered
// (event id, result hash) pairs in a window. It gives the control plane a stable
// handle for the exact set of audited decisions a rollup's counts summarize --
// enough to detect a duplicate or stale window, and enough for an auditor to
// cross-check against the node's local audit chain during an on-site review --
// without any event content ever leaving the node. Samples missing both an
// event id and a result hash contribute nothing, so a caller that cannot supply
// them still gets a valid (empty-input) digest.
func WindowDigest(samples []Sample) string {
	h := sha256.New()
	for _, s := range samples {
		if s.EventID == "" && s.ResultHash == "" {
			continue
		}
		h.Write([]byte(s.EventID))
		h.Write([]byte{0})
		h.Write([]byte(s.ResultHash))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Aggregate is the residency-safe reduction of a window of Samples: nothing but
// counts. It is what Build stamps into a Rollup.
type Aggregate struct {
	Decisions DecisionCounts `json:"decisions"`
	ByCheck   map[string]int `json:"by_check"` // keyed by IntentGate check name
	Agents    int            `json:"agents"`   // distinct agent count only
	Tools     int            `json:"tools"`    // distinct tool count only
	Sessions  int            `json:"sessions"` // distinct session count only
}

// Summarize reduces a window of Samples to an Aggregate. Distinct identifiers
// are counted in local sets that never leave the function; only the resulting
// integers are returned. Unknown or empty decision values still contribute to
// Total so the aggregate always reconciles.
func Summarize(samples []Sample) Aggregate {
	agg := Aggregate{ByCheck: map[string]int{}}
	agents := map[string]struct{}{}
	tools := map[string]struct{}{}
	sessions := map[string]struct{}{}
	for _, s := range samples {
		agg.Decisions.Total++
		switch s.Decision {
		case "allow":
			agg.Decisions.Allow++
		case "escalate":
			agg.Decisions.Hold++
		case "block":
			agg.Decisions.Deny++
		}
		if s.Check != "" {
			agg.ByCheck[s.Check]++
		}
		if s.Agent != "" {
			agents[s.Agent] = struct{}{}
		}
		if s.Tool != "" {
			tools[s.Tool] = struct{}{}
		}
		if s.Session != "" {
			sessions[s.Session] = struct{}{}
		}
	}
	agg.Agents = len(agents)
	agg.Tools = len(tools)
	agg.Sessions = len(sessions)
	return agg
}

// Rollup is the zero-payload telemetry a data-plane node pushes up to the
// control plane. Every field is either the node's own identity, a time bound,
// an integer count, or a hash. There is intentionally no field that can carry a
// customer payload, an identifier, or free text drawn from a request.
type Rollup struct {
	Version     string         `json:"version"`
	NodeID      string         `json:"node_id"`      // the data-plane node's stable identity
	Tenant      string         `json:"tenant"`       // trust domain within the node, optional
	WindowFrom  string         `json:"window_from"`  // RFC3339, inclusive
	WindowTo    string         `json:"window_to"`    // RFC3339, exclusive
	GeneratedAt string         `json:"generated_at"` // RFC3339
	Decisions   DecisionCounts `json:"decisions"`
	ByCheck     map[string]int `json:"by_check"`
	Agents      int            `json:"agents"`
	Tools       int            `json:"tools"`
	Sessions    int            `json:"sessions"`
	AuditHead   string         `json:"audit_head"`          // hash of the local audit chain head, never event content
	KeyID       string         `json:"key_id"`              // identifier of the signing key, never the key
	Signature   string         `json:"signature,omitempty"` // hex HMAC-SHA256 over the rollup sans this field
}

// Build assembles an unsigned rollup from an already-computed Aggregate. Like
// proofofintent.Build it does not reach into the audit store, so it stays
// trivially testable and the residency-relevant reduction lives entirely in
// Summarize, which the caller runs first.
func Build(nodeID, tenant string, from, to time.Time, agg Aggregate, auditHead string, now time.Time) Rollup {
	byCheck := agg.ByCheck
	if byCheck == nil {
		byCheck = map[string]int{}
	}
	return Rollup{
		Version:     RollupVersion,
		NodeID:      nodeID,
		Tenant:      tenant,
		WindowFrom:  from.UTC().Format(time.RFC3339),
		WindowTo:    to.UTC().Format(time.RFC3339),
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Decisions:   agg.Decisions,
		ByCheck:     byCheck,
		Agents:      agg.Agents,
		Tools:       agg.Tools,
		Sessions:    agg.Sessions,
		AuditHead:   auditHead,
	}
}

// CanonicalString returns the deterministic, cross-language signing form of a
// rollup: a fixed-order, newline-delimited string with by_check keys sorted.
// Both this Go signer and the control-plane (TypeScript) verifier build exactly
// these bytes, so the HMAC matches without depending on JSON field ordering,
// whitespace, or map iteration order. The leading tag pins the format version so
// a future change to the field set cannot silently mis-verify an old rollup.
func CanonicalString(r Rollup) string {
	keys := make([]string, 0, len(r.ByCheck))
	for k := range r.ByCheck {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	checks := make([]string, 0, len(keys))
	for _, k := range keys {
		checks = append(checks, k+"="+strconv.Itoa(r.ByCheck[k]))
	}
	lines := []string{
		"fed-rollup-canonical-v1",
		r.Version,
		r.NodeID,
		r.Tenant,
		r.WindowFrom,
		r.WindowTo,
		r.GeneratedAt,
		strconv.Itoa(r.Decisions.Allow),
		strconv.Itoa(r.Decisions.Hold),
		strconv.Itoa(r.Decisions.Deny),
		strconv.Itoa(r.Decisions.Total),
		strings.Join(checks, ","),
		strconv.Itoa(r.Agents),
		strconv.Itoa(r.Tools),
		strconv.Itoa(r.Sessions),
		r.AuditHead,
	}
	return strings.Join(lines, "\n")
}

// Sign stamps the key id and computes the HMAC-SHA256 signature over the
// canonical rollup. The key is the dedicated per-node federation signing key
// (never the capability master key); it is never stored in the rollup.
func Sign(r *Rollup, keyID string, key []byte) error {
	r.KeyID = keyID
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(CanonicalString(*r)))
	r.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify recomputes the signature with key and returns (true, "verified") only
// when it matches. A rollup altered by one byte -- a bumped count, a changed
// node id, a spliced check -- fails. Intended for a Go-side verifier and tests;
// the control plane verifies the same construction in its ingest endpoint.
func Verify(r Rollup, key []byte) (bool, string) {
	if r.Signature == "" {
		return false, "unsigned"
	}
	want, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false, "malformed_signature"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(CanonicalString(r)))
	if !hmac.Equal(mac.Sum(nil), want) {
		return false, "signature_mismatch"
	}
	return true, "verified"
}
