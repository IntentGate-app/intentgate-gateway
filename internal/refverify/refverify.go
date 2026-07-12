// Package refverify is the reference-verification (four-eyes-on-the-payee)
// control that sits alongside the effect-level action guard. Before a PAYMENT
// tool call executes, it verifies the payee/destination against a vendor-master
// reference — the system of record for who may be paid (e.g. SAP).
//
//	match            -> allow  (fall through to the rest of the pipeline)
//	mismatch/unknown -> quarantine (pause for human approval)
//	source down      -> quarantine (fail-closed: never pay a payee we cannot verify)
//
// Non-payment calls are ignored. The vendor master is reached through the
// VendorMaster seam: today an embedded, normalized allowlist (StaticVendorMaster);
// later a live connector to the system of record. Everything here is
// deterministic — the same master and call always yield the same verdict.
package refverify

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// Verdict is refverify's decision. It maps onto the gateway's existing
// allow / block / escalate semantics (quarantine == pause for human approval).
type Verdict string

const (
	VerdictAllow      Verdict = "allow"
	VerdictQuarantine Verdict = "quarantine"
	VerdictBlock      Verdict = "block"
)

// Record is one entry in the vendor master: an approved payee and its
// authoritative name.
type Record struct {
	Payee string `json:"payee"`
	Name  string `json:"name"`
}

// VendorMaster is the connector seam to the system of record. Lookup returns
// the matching record and true when the payee is known, false when it is not,
// and a non-nil error when the reference source could not be consulted (which
// the verifier treats fail-closed). Implementations must be safe for
// concurrent use.
type VendorMaster interface {
	Lookup(payee string) (Record, bool, error)
}

var reSpace = regexp.MustCompile(`\s+`)

// normKey normalizes a payee identifier for lookup: uppercase, spaces stripped.
func normKey(s string) string {
	return strings.ToUpper(reSpace.ReplaceAllString(strings.TrimSpace(s), ""))
}

// normName normalizes an asserted name for comparison: lower-case, single
// spaces, trimmed (case-insensitive equality on the human-readable name).
func normName(s string) string {
	return strings.TrimSpace(reSpace.ReplaceAllString(strings.ToLower(s), " "))
}

// StaticVendorMaster is an in-memory VendorMaster backed by a normalized map.
// It is the embedded allowlist used before a live system-of-record connector is
// wired in. Optional aliases fold onto the same Record.
type StaticVendorMaster struct {
	byKey map[string]Record
}

// NewStaticVendorMaster builds a static master from the given records. Keys are
// normalized (uppercased, spaces stripped) so lookups are drift-resistant.
func NewStaticVendorMaster(records []Record) *StaticVendorMaster {
	m := &StaticVendorMaster{byKey: make(map[string]Record, len(records))}
	for _, r := range records {
		if k := normKey(r.Payee); k != "" {
			m.byKey[k] = r
		}
	}
	return m
}

// addAlias points an additional key at an existing record (same payee, different
// spelling/identifier). Used by LoadConfigFile to fold aliases in.
func (m *StaticVendorMaster) addAlias(alias string, r Record) {
	if k := normKey(alias); k != "" {
		m.byKey[k] = r
	}
}

// Lookup implements VendorMaster. It never errors: an in-memory master is
// always available.
func (m *StaticVendorMaster) Lookup(payee string) (Record, bool, error) {
	r, ok := m.byKey[normKey(payee)]
	return r, ok, nil
}

// Config tunes reference verification.
type Config struct {
	// Master is the vendor-master reference. nil means the source is
	// unavailable; when FailClosed is set, payments quarantine.
	Master VendorMaster
	// MinCents: only verify payments whose MagnitudeCents is at least this.
	// 0 verifies all payments.
	MinCents int64
	// FailClosed decides what happens when the payee cannot be verified
	// (no payee on the call, or no reference source). Default true: hold.
	FailClosed bool
}

// Verifier applies reference verification. Stateless and safe for concurrent
// use (state, if any, lives behind the VendorMaster).
type Verifier struct {
	cfg Config
}

// New returns a Verifier with the given config.
func New(cfg Config) *Verifier {
	return &Verifier{cfg: cfg}
}

// Result is the verifier's verdict plus the resolved IR and which rule fired.
type Result struct {
	Verdict Verdict
	Reason  string
	Rule    string // stable identifier of the rule that fired, "" on plain allow
	IR      actionir.ActionIR
}

// Check resolves the call and, when it is a payment above the threshold,
// verifies the payee against the vendor master. Non-payment calls and
// below-threshold payments fall through to allow.
func (v *Verifier) Check(tool string, args map[string]any) Result {
	ir := actionir.Resolve(tool, args)

	// Only payments are subject to reference verification.
	if ir.Op != actionir.OpPay {
		return Result{VerdictAllow, "", "refverify.not_payment", ir}
	}

	// Below the verification threshold: not worth a human's time.
	if v.cfg.MinCents > 0 && ir.MagnitudeCents < v.cfg.MinCents {
		return Result{VerdictAllow, "", "refverify.below_threshold", ir}
	}

	// No payee to verify. Fail-closed: hold rather than pay blind.
	payee := ir.Destination
	if payee == "" {
		if v.cfg.FailClosed {
			return Result{VerdictQuarantine, "payment has no identifiable payee to verify", "refverify.no_payee", ir}
		}
		return Result{VerdictAllow, "", "refverify.no_payee", ir}
	}

	// No reference source. Fail-closed: never pay a payee we cannot verify.
	if v.cfg.Master == nil {
		if v.cfg.FailClosed {
			return Result{VerdictQuarantine, "vendor-master reference is unavailable", "refverify.no_source", ir}
		}
		return Result{VerdictAllow, "", "refverify.no_source", ir}
	}

	rec, ok, err := v.cfg.Master.Lookup(payee)
	if err != nil {
		return Result{
			VerdictQuarantine,
			fmt.Sprintf("vendor-master lookup for %q failed: %v", payee, err),
			"refverify.source_unavailable", ir,
		}
	}
	if !ok {
		return Result{
			VerdictQuarantine,
			fmt.Sprintf("payee %q is not in the vendor master", payee),
			"refverify.payee_not_in_master", ir,
		}
	}

	// Payee is known. If the call also asserts a payee NAME, it must match the
	// name of record — a mismatch is the classic account/name-swap fraud.
	if claimed := assertedName(args); claimed != "" && rec.Name != "" &&
		normName(claimed) != normName(rec.Name) {
		return Result{
			VerdictQuarantine,
			fmt.Sprintf("asserted payee name %q does not match vendor master (%q) for %q", claimed, rec.Name, payee),
			"refverify.name_mismatch", ir,
		}
	}

	return Result{VerdictAllow, "", "refverify.match", ir}
}

// assertedName pulls a claimed payee name from the call args, if one is present.
func assertedName(args map[string]any) string {
	for k, val := range args {
		switch strings.ToLower(k) {
		case "payee_name", "beneficiary_name", "name":
			if s, ok := val.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

// LoadConfigFile reads a vendor-master JSON file of shape
//
//	{"vendors":[{"payee":"...","name":"...","aliases":["..."]}]}
//
// and returns the flat list of records. Aliases are folded in as additional
// records pointing at the same authoritative name, so NewStaticVendorMaster
// indexes each alias as its own lookup key.
func LoadConfigFile(path string) ([]Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		Vendors []struct {
			Payee   string   `json:"payee"`
			Name    string   `json:"name"`
			Aliases []string `json:"aliases"`
		} `json:"vendors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("invalid vendor-master config: %w", err)
	}
	out := make([]Record, 0, len(file.Vendors))
	for _, v := range file.Vendors {
		rec := Record{Payee: v.Payee, Name: v.Name}
		out = append(out, rec)
		for _, alias := range v.Aliases {
			out = append(out, Record{Payee: alias, Name: v.Name})
		}
	}
	return out, nil
}
