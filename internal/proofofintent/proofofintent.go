// Package proofofintent packages the gateway's existing hash-chained audit
// trail into a cryptographically signed, tamper-evident compliance bundle
// (audit and compliance). It links the originating declared intent directly
// to the executed action and its result hash, and to the audit chain that
// recorded it, so a SOC team or an auditor gets one-click, cryptographically
// verified proof of WHY an action was permitted.
//
// The bundle is honest evidence, not a score: every field is copied from a
// real audit event (intent summary, tool, decision, reason, result SHA-256,
// and the chain's prev_hash/hash), the whole bundle is HMAC-SHA256 signed
// with the gateway master key, and Verify recomputes that signature and
// re-checks the internal chain linkage. Nothing is invented; a bundle that
// has been altered by a byte fails verification.
//
// This delivers EU AI Act (Article 12 record-keeping, Article 14 human
// oversight evidence) and SOC 2 (CC7) readiness without adding any fake risk
// scoring: the proof is the signature and the chain, both checkable offline.
package proofofintent

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// BundleVersion is the schema version stamped into every bundle. Bump it if
// the signed field set changes, so an old bundle never silently mis-verifies.
const BundleVersion = "poi-1"

// Entry is one decision, copied verbatim from a real audit event. The link
// the auditor cares about lives here: IntentSummary (why) -> Tool/Decision
// (what) -> ResultSHA256 (the exact bytes returned) -> Hash (its place in the
// tamper-evident chain).
type Entry struct {
	EventID       string `json:"event_id"`
	Ts            string `json:"ts"`
	Agent         string `json:"agent"`
	Tool          string `json:"tool"`
	Decision      string `json:"decision"`
	Check         string `json:"check"`
	Reason        string `json:"reason"`
	IntentSummary string `json:"intent_summary"`
	ResultSHA256  string `json:"result_sha256"`
	PrevHash      string `json:"prev_hash"`
	Hash          string `json:"hash"`
}

// Bundle is a signed export covering one decision or a whole session.
type Bundle struct {
	Version     string  `json:"version"`
	Tenant      string  `json:"tenant"`
	Subject     string  `json:"subject"` // decision id or session id this bundle proves
	GeneratedAt string  `json:"generated_at"`
	Entries     []Entry `json:"entries"`
	KeyID       string  `json:"key_id"`             // identifier of the signing key, never the key itself
	Signature   string  `json:"signature,omitempty"` // hex HMAC-SHA256 over the bundle sans this field
}

// Build assembles an unsigned bundle. Callers pass entries already read from
// the audit store; this package does not reach into the database so it stays
// trivially testable and reusable by the console and a CLI verifier alike.
func Build(tenant, subject string, entries []Entry, now time.Time) Bundle {
	return Bundle{
		Version:     BundleVersion,
		Tenant:      tenant,
		Subject:     subject,
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Entries:     entries,
	}
}

// canonicalBytes returns the deterministic bytes that are signed: the bundle
// with the Signature field cleared. json.Marshal emits struct fields in
// declaration order and sorts map keys, so the encoding is stable.
func canonicalBytes(b Bundle) ([]byte, error) {
	b.Signature = ""
	return json.Marshal(b)
}

// Sign stamps the key id and computes the HMAC-SHA256 signature over the
// canonical bundle. The key is the gateway master key (or a derived signing
// key); it is never stored in the bundle.
func Sign(b *Bundle, keyID string, key []byte) error {
	b.KeyID = keyID
	canon, err := canonicalBytes(*b)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	b.Signature = hex.EncodeToString(mac.Sum(nil))
	return nil
}

// Verify recomputes the signature with key and re-checks the internal chain
// linkage. It returns (true, "verified") only when the signature matches and
// every entry's prev_hash equals the previous entry's hash. Any tamper - a
// changed reason, a reordered entry, a spliced row - breaks one of the two.
func Verify(b Bundle, key []byte) (bool, string) {
	if b.Signature == "" {
		return false, "unsigned"
	}
	want, err := hex.DecodeString(b.Signature)
	if err != nil {
		return false, "malformed_signature"
	}
	canon, err := canonicalBytes(b)
	if err != nil {
		return false, "encode_error"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	if !hmac.Equal(mac.Sum(nil), want) {
		return false, "signature_mismatch"
	}
	// Chain linkage: consecutive entries must be adjacent in the audit chain.
	// Empty hashes are tolerated (older gateways did not persist them) so the
	// signature remains the primary proof.
	for i := 1; i < len(b.Entries); i++ {
		prev := b.Entries[i-1].Hash
		cur := b.Entries[i].PrevHash
		if prev != "" && cur != "" && prev != cur {
			return false, "chain_break"
		}
	}
	return true, "verified"
}
