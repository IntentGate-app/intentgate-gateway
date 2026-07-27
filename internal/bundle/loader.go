package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUnsigned is returned when a bundle has no signature and the registry is not
// explicitly running in dev mode (AllowUnsigned=false, the default).
var ErrUnsigned = errors.New("bundle is unsigned and AllowUnsigned is false")

// BundleRegistry holds the active compiled bundle per subject and swaps it
// atomically. Reads go through sync.Map, so a swap replaces the pointer for one
// subject without locking or touching others: live traffic never stalls. This
// is the multi-subject generalisation of a single atomic.Pointer swap.
type BundleRegistry struct {
	bySubject sync.Map // subject(string) -> *CompiledGateBundle
	publicKey ed25519.PublicKey

	// AllowUnsigned permits loading bundles without a valid signature. DEV ONLY.
	// Production leaves this false, so verification fails closed.
	AllowUnsigned bool
}

// NewBundleRegistry returns a registry that verifies bundles against pub.
func NewBundleRegistry(pub ed25519.PublicKey) *BundleRegistry {
	return &BundleRegistry{publicKey: pub}
}

// Canonical returns the exact bytes that are signed and digested. It mirrors
// console-pro/lib/intentgrant/signer.ts: an explicit "signing view" (every field
// always present, set-arrays sorted, timestamps second-precision UTC) rendered
// as JCS (RFC 8785: keys sorted, no whitespace). The compiler MUST produce these
// same bytes or signatures will not verify. A golden vector in
// canonical_golden_test.go pins the cross-language agreement.
func Canonical(b *CompiledGateBundle) []byte {
	return []byte(jcs(signingView(b)))
}

// Digest is the hex SHA-256 over the canonical bundle: the audit reference that
// pins exactly which ruleset was in force for a decision.
func Digest(b *CompiledGateBundle) (string, error) {
	sum := sha256.Sum256(Canonical(b))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Verify checks the Ed25519 signature over the canonical bundle.
func (r *BundleRegistry) Verify(b *CompiledGateBundle) error {
	if len(b.Signature) == 0 {
		if r.AllowUnsigned {
			return nil
		}
		return ErrUnsigned
	}
	if len(r.publicKey) == 0 {
		return errors.New("no public key configured to verify bundle signature")
	}
	if !ed25519.Verify(r.publicKey, Canonical(b), b.Signature) {
		return errors.New("invalid bundle signature: untrusted policy compiler artifact")
	}
	return nil
}

// LoadAndSwap verifies the bundle and atomically installs it as the active
// ruleset for its subject, with zero downtime for other subjects.
func (r *BundleRegistry) LoadAndSwap(b *CompiledGateBundle) error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if b.StaticCapabilities.Subject == "" {
		return errors.New("bundle has no subject")
	}
	if err := r.Verify(b); err != nil {
		return fmt.Errorf("verify bundle %s: %w", b.BundleID, err)
	}
	r.bySubject.Store(b.StaticCapabilities.Subject, b)
	return nil
}

// GetActive returns the active bundle for a subject, or nil if none is loaded.
func (r *BundleRegistry) GetActive(subject string) *CompiledGateBundle {
	v, ok := r.bySubject.Load(subject)
	if !ok {
		return nil
	}
	return v.(*CompiledGateBundle)
}

// Remove drops a subject's active bundle (revocation).
func (r *BundleRegistry) Remove(subject string) {
	r.bySubject.Delete(subject)
}

/* ---------------------------- canonicalization --------------------------- */

// signingView builds the exact object the signer canonicalizes. Keep this in
// lockstep with signingView() in signer.ts.
func signingView(b *CompiledGateBundle) map[string]any {
	c := b.StaticCapabilities.Caveats

	agEnabled := b.RuntimeGuardRules.ActionGuard != nil
	var agInspect bool
	var agIrrev []string
	var agMax int64
	var agOn string
	if ag := b.RuntimeGuardRules.ActionGuard; ag != nil {
		agInspect = ag.InspectPayload
		agIrrev = ag.IrreversibleActions
		agMax = ag.MagnitudeCheck.MaxCents
		agOn = ag.MagnitudeCheck.OnExceeded
	}

	var vmEnabled bool
	var vmCheck string
	if rv := b.RuntimeGuardRules.ReferenceVerification; rv != nil {
		vmEnabled = rv.VendorMaster.Enabled
		vmCheck = rv.VendorMaster.CheckType
	}

	return map[string]any{
		"bundle_id":      b.BundleID,
		"grant_id":       b.GrantID,
		"version":        b.Version,
		"compiled_at":    utcSeconds(b.CompiledAt),
		"subject":        b.StaticCapabilities.Subject,
		"delegated_from": b.StaticCapabilities.DelegatedFrom,
		"caveats": map[string]any{
			"allowed_tools":            sortedCopy(c.AllowedTools),
			"allowed_mcp_servers":      sortedCopy(c.AllowedMcpServers),
			"zone":                     c.Zone,
			"valid_until":              utcSeconds(c.ValidUntil),
			"max_execution_cost_cents": c.MaxExecutionCostCents,
			"rate_limit_per_min":       int64(c.RateLimitPerMin),
			"max_calls":                int64(c.MaxCalls),
			"max_risk_score":           int64(c.MaxRiskScore),
			"observe_only":             c.ObserveOnly,
		},
		"runtime_guard": map[string]any{
			"actionguard": map[string]any{
				"enabled":              agEnabled,
				"inspect_payload":      agInspect,
				"irreversible_actions": sortedCopy(agIrrev),
				"max_cents":            agMax,
				"on_exceeded":          agOn,
			},
			"vendor_master": map[string]any{
				"enabled":    vmEnabled,
				"check_type": vmCheck,
			},
		},
		"attestation": map[string]any{
			"emit_proof":   b.AttestationConfig.EmitProof,
			"proof_domain": b.AttestationConfig.ProofDomain,
		},
	}
}

// utcSeconds formats a time as second-precision UTC ISO-8601, or "" if zero.
func utcSeconds(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05") + "Z"
}

// sortedCopy returns a sorted copy; nil becomes a non-nil empty slice so it
// canonicalizes as "[]" (matching the TS side), never "null".
func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// jcs renders a value as RFC-8785-style canonical JSON: object keys sorted, no
// whitespace. Only the types used by signingView are handled.
func jcs(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case string:
		return jstr(t)
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case []string:
		parts := make([]string, len(t))
		for i, s := range t {
			parts[i] = jstr(s)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = jstr(k) + ":" + jcs(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		panic(fmt.Sprintf("jcs: unsupported type %T", v))
	}
}

// jstr JSON-encodes a string without HTML escaping, matching JavaScript's
// JSON.stringify (Go's default would escape <, >, & to \u00xx).
func jstr(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}
