// Package sessionrewind is the self-healing session rewind engine (resilience).
// When an outbound action is blocked, a normal gateway returns a raw error that
// leaves the agent's context poisoned (it keeps trying bad actions) or forces
// the whole session to be killed (the user loses all progress). Session rewind
// is the third option: block the action, roll the agent back to the last
// verified-safe checkpoint, and hand it a signed correction so it heals and
// continues.
//
// What is real and in the gateway's hands:
//
//   - Checkpoints. The gateway already records every decision of a session in
//     order (the audit trail). Each allowed step is a verified-safe state, so
//     the "last good checkpoint" needs no new plumbing - it is derived from the
//     real sequence, with a chained hash so a checkpoint id also proves the
//     clean prefix it stands for was not altered.
//   - The recovery envelope. On a block the gateway returns a signed envelope
//     naming the checkpoint to roll back to and the inoculation note to inject,
//     instead of a raw 403.
//
// The honest boundary: the gateway sits in the tool-call path, not inside the
// model's context window, so it emits the rollback point and the correction;
// the agent runtime / SDK applies the rewind by consuming the envelope. This is
// cooperative rewind, not the gateway silently editing the model's memory.
//
// Everything here is deterministic and local: hashing is SHA-256 over the real
// step sequence, the envelope is HMAC-SHA256 signed with the gateway key, and
// the inoculation note never echoes attacker content (only the tool name and
// the policy reason).
package sessionrewind

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Decision values a step can carry, matching the audit decisions.
const (
	DecisionAllow    = "allow"
	DecisionBlock    = "block"
	DecisionEscalate = "escalate"
)

// Step is one decision in a session, in order, copied from the audit trail.
type Step struct {
	EventID  string `json:"event_id"`
	Ts       string `json:"ts"`
	Tool     string `json:"tool"`
	Decision string `json:"decision"`
}

// Checkpoint is a verified-safe state: the point just after an allowed call.
// The agent can be rewound here.
type Checkpoint struct {
	Seq     int    `json:"seq"`
	EventID string `json:"event_id"`
	Ts      string `json:"ts"`
	Tool    string `json:"tool"`
	// Hash chains the previous checkpoint, so this id also proves the clean
	// prefix it represents was not altered.
	Hash string `json:"hash"`
}

// BuildCheckpoints returns one checkpoint per allowed step, in order.
func BuildCheckpoints(steps []Step) []Checkpoint {
	var cps []Checkpoint
	prev := "root"
	for i, s := range steps {
		if s.Decision != DecisionAllow {
			continue
		}
		sum := sha256.Sum256([]byte(prev + "|" + s.EventID + "|" + s.Tool))
		h := hex.EncodeToString(sum[:])
		cps = append(cps, Checkpoint{Seq: i, EventID: s.EventID, Ts: s.Ts, Tool: s.Tool, Hash: h})
		prev = h
	}
	return cps
}

// LastSafe returns the most recent checkpoint, if any.
func LastSafe(cps []Checkpoint) (Checkpoint, bool) {
	if len(cps) == 0 {
		return Checkpoint{}, false
	}
	return cps[len(cps)-1], true
}

// EnvelopeVersion is stamped into every recovery envelope.
const EnvelopeVersion = "rewind-1"

// RecoveryEnvelope is returned on a block instead of a raw error. It names the
// safe checkpoint to rewind to and the correction to inject, and is signed so
// the agent runtime can trust it.
type RecoveryEnvelope struct {
	Version           string `json:"version"`
	SessionID         string `json:"session_id"`
	BlockedTool       string `json:"blocked_tool"`
	BlockedReason     string `json:"blocked_reason"`
	RolledBackTo      string `json:"rolled_back_to"`       // checkpoint hash, "" when none exists
	RolledBackEventID string `json:"rolled_back_event_id"` // "" when none exists
	SystemNote        string `json:"system_note"`
	GeneratedAt       string `json:"generated_at"`
	KeyID             string `json:"key_id"`
	Signature         string `json:"signature,omitempty"`
}

// Inoculate builds the system note injected to heal the agent. It names the
// restricted action and the policy reason only, never any attacker content, so
// the correction itself cannot become a new injection vector.
func Inoculate(tool, reason string) string {
	return fmt.Sprintf(
		"System note: tool execution for %q was restricted due to a safety constraint (%s). "+
			"The previous step has been rolled back to the last verified-safe checkpoint. "+
			"Re-evaluate alternative, user-approved paths and do not retry the restricted action.",
		tool, reason,
	)
}

// BuildEnvelope assembles an unsigned recovery envelope for a blocked step. If
// hasSafe is false (the block happened before any allowed step), the rollback
// target is empty and the agent restarts from session origin.
func BuildEnvelope(sessionID, blockedTool, reason string, last Checkpoint, hasSafe bool, now time.Time) RecoveryEnvelope {
	env := RecoveryEnvelope{
		Version:       EnvelopeVersion,
		SessionID:     sessionID,
		BlockedTool:   blockedTool,
		BlockedReason: reason,
		SystemNote:    Inoculate(blockedTool, reason),
		GeneratedAt:   now.UTC().Format(time.RFC3339),
	}
	if hasSafe {
		env.RolledBackTo = last.Hash
		env.RolledBackEventID = last.EventID
	}
	return env
}

func canonicalBytes(e RecoveryEnvelope) ([]byte, error) {
	e.Signature = ""
	return json.Marshal(e)
}

// Sign stamps the key id and HMAC-SHA256 signs the envelope. The key never
// leaves the gateway.
func Sign(e *RecoveryEnvelope, keyID string, key []byte) error {
	e.KeyID = keyID
	c, err := canonicalBytes(*e)
	if err != nil {
		return err
	}
	m := hmac.New(sha256.New, key)
	m.Write(c)
	e.Signature = hex.EncodeToString(m.Sum(nil))
	return nil
}

// Verify recomputes the signature so the agent runtime can trust the envelope
// before acting on it. Any tamper - a changed rollback target or note - fails.
func Verify(e RecoveryEnvelope, key []byte) (bool, string) {
	if e.Signature == "" {
		return false, "unsigned"
	}
	want, err := hex.DecodeString(e.Signature)
	if err != nil {
		return false, "malformed_signature"
	}
	c, err := canonicalBytes(e)
	if err != nil {
		return false, "encode_error"
	}
	m := hmac.New(sha256.New, key)
	m.Write(c)
	if !hmac.Equal(m.Sum(nil), want) {
		return false, "signature_mismatch"
	}
	return true, "verified"
}
