// Package actionir is IntentGate's Semantic Action Resolver.
//
// It turns a raw agent tool call (a tool name plus a bag of arguments) into a
// canonical, deterministic description of what the call will actually DO: the
// Action IR. Policy then evaluates the effect, not the surface string.
//
// The point is to defeat "representational drift": two calls that look
// different (different casing, encoding, quoting, or number formatting) but
// have the same real effect must resolve to the SAME Action IR, so a policy
// written once cannot be evaded by obfuscation.
//
// Deterministic by construction: the same input always yields the same Action
// IR. No model is consulted.
//
// NOTE (V1): the obfuscation handling here covers the common bypass classes
// (encoding, quoting, spacing, number-format drift). Hardening against novel
// obfuscation is ongoing and driven by a red-team corpus; this is the first
// cut, not the finished canonicalizer.
package actionir

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Op is the canonical operation an action performs.
type Op string

const (
	OpRead    Op = "read"    // reversible, no state change
	OpCreate  Op = "create"  // adds state (a supplier, a record)
	OpWrite   Op = "write"   // modifies state
	OpDelete  Op = "delete"  // removes state (usually irreversible)
	OpPay     Op = "pay"     // moves money / places an order (irreversible, high value)
	OpExecute Op = "execute" // runs code / a command
	OpSend    Op = "send"    // sends a message / email outward
	OpUnknown Op = "unknown" // unrecognised; treat conservatively
)

// Scope describes how broad the action's blast radius is.
type Scope string

const (
	ScopeSingle    Scope = "single"    // one record / target
	ScopeBounded   Scope = "bounded"   // a filtered set
	ScopeUnbounded Scope = "unbounded" // everything (no filter, wildcard, or "all")
)

// ActionIR is the canonical effect of a tool call. Policy evaluates this.
type ActionIR struct {
	Op             Op       `json:"op"`
	Resource       string   `json:"resource"`              // e.g. "supplier", "invoice", "order", "database"
	Scope          Scope    `json:"scope"`                 // single | bounded | unbounded
	MagnitudeCents int64    `json:"magnitude_cents"`       // financial magnitude in cents; 0 if not financial
	Currency       string   `json:"currency,omitempty"`    // e.g. "EUR"
	Destination    string   `json:"destination,omitempty"` // payee / target / recipient
	Reversible     bool     `json:"reversible"`            // can the effect be undone?
	Canonical      string   `json:"canonical"`             // normalised, decoded string form (for audit)
	Signals        []string `json:"signals,omitempty"`     // notes: "decoded_base64", "deobfuscated", ...
}

// Dangerous verbs are matched as plain substrings on the tight (punctuation
// removed) form, so obfuscation like de”lete or d-e-l-e-t-e cannot hide them.
// Fail-safe: over-flagging a dangerous op is safer than missing one. These are
// chosen to rarely appear as substrings of benign words.
var (
	dangerDelete = []string{"delete", "drop", "truncate", "destroy", "wipe", "purge"}
	dangerPay    = []string{"payment", "transfer", "purchase", "checkout", "remit", "disburse"}
	dangerExec   = []string{"execute", "shell", "spawn", "system", "eval"}
)

// Benign verbs are matched with word boundaries on the spaced form, to avoid
// false positives from substrings.
var (
	reVerbPay    = regexp.MustCompile(`\b(pay|order|wire)\b`)
	reVerbCreate = regexp.MustCompile(`\b(create|add|new|register|onboard|insert)\b`)
	reVerbWrite  = regexp.MustCompile(`\b(update|write|modify|edit|approve|set|patch|put)\b`)
	reVerbSend   = regexp.MustCompile(`\b(send|email|mail|notify|dispatch)\b`)
	reVerbRead   = regexp.MustCompile(`\b(read|get|list|fetch|view|show|lookup|search|query|select)\b`)
	reVerbDelSp  = regexp.MustCompile(`\b(delete|drop|truncate|destroy|wipe|purge|remove)\b`)
	reUnbounded  = regexp.MustCompile(`\b(all|everything|any|entire|global)\b`)
	reNoun       = regexp.MustCompile(`\b(supplier|vendor|invoice|order|payment|customer|employee|record|table|database|file|user|account|purchase)\b`)
	reHex        = regexp.MustCompile(`^[0-9a-fA-F]{6,}$`)
	reB64        = regexp.MustCompile(`^[A-Za-z0-9+/]{6,}={0,2}$`)
	reMoney      = regexp.MustCompile(`[0-9][0-9.,_ ]*[0-9]|[0-9]`)
	reNonAlnum   = regexp.MustCompile(`[^a-z0-9]+`)
)

// Resolve canonicalises a tool call into its Action IR. Deterministic.
func Resolve(tool string, args map[string]any) ActionIR {
	signals := []string{}

	// 1. Decode + lowercase the tool name and every string arg, then join.
	parts := []string{decodeToken(tool, &signals)}
	for _, v := range args {
		if s, ok := v.(string); ok {
			parts = append(parts, decodeToken(s, &signals))
		}
	}
	combined := strings.Join(parts, " ")

	// 2. Two normalised views:
	//    spaced: punctuation -> space (keeps word boundaries for benign verbs)
	//    tight : punctuation removed  (joins de''lete -> delete for danger scan)
	spaced := " " + strings.Join(strings.Fields(reNonAlnum.ReplaceAllString(combined, " ")), " ") + " "
	tight := reNonAlnum.ReplaceAllString(combined, "")

	// 3. Classify the operation.
	op := classify(spaced, tight)
	if op == OpDelete && !reVerbDelSp.MatchString(spaced) {
		signals = append(signals, "deobfuscated")
	}

	// 4. Resource (best-effort noun).
	resource := reNoun.FindString(spaced)

	// 5. Scope.
	scope := ScopeSingle
	if reUnbounded.MatchString(spaced) {
		scope = ScopeUnbounded
	} else if hasFilterKey(args) {
		scope = ScopeBounded
	}

	// 6. Financial magnitude (drift-resistant).
	cents, currency := extractAmount(args)

	// 7. Destination.
	dest := firstStringKey(args, "payee", "supplier", "vendor", "to", "recipient", "account", "destination", "beneficiary")

	// 8. Reversibility.
	reversible := true
	switch op {
	case OpDelete, OpPay, OpExecute, OpSend:
		reversible = false
	}

	return ActionIR{
		Op:             op,
		Resource:       resource,
		Scope:          scope,
		MagnitudeCents: cents,
		Currency:       currency,
		Destination:    dest,
		Reversible:     reversible,
		Canonical:      strings.TrimSpace(combined),
		Signals:        dedup(signals),
	}
}

// classify picks the operation. Dangerous ops are scanned as substrings on the
// tight form (obfuscation-proof, fail-safe); benign ops use bounded matches on
// the spaced form. Most dangerous wins.
func classify(spaced, tight string) Op {
	switch {
	case containsAny(tight, dangerDelete):
		return OpDelete
	case containsAny(tight, dangerPay) || reVerbPay.MatchString(spaced):
		return OpPay
	case containsAny(tight, dangerExec):
		return OpExecute
	case reVerbCreate.MatchString(spaced):
		return OpCreate
	case reVerbWrite.MatchString(spaced):
		return OpWrite
	case reVerbSend.MatchString(spaced):
		return OpSend
	case reVerbRead.MatchString(spaced):
		return OpRead
	default:
		return OpUnknown
	}
}

// decodeToken base64/hex-decodes a token when it looks encoded, then lowercases.
func decodeToken(s string, signals *[]string) string {
	s = strings.TrimSpace(s)
	if reB64.MatchString(s) {
		if dec, err := base64.StdEncoding.DecodeString(s); err == nil && isMostlyPrintable(dec) {
			s = string(dec)
			*signals = append(*signals, "decoded_base64")
		}
	}
	if reHex.MatchString(s) && len(s)%2 == 0 {
		if dec, err := hex.DecodeString(s); err == nil && isMostlyPrintable(dec) {
			s = string(dec)
			*signals = append(*signals, "decoded_hex")
		}
	}
	return strings.ToLower(s)
}

// decodeOnly is like decodeToken but keeps separators (for money parsing) and
// raises no signals.
func decodeOnly(s string) string {
	s = strings.TrimSpace(s)
	if reB64.MatchString(s) {
		if dec, err := base64.StdEncoding.DecodeString(s); err == nil && isMostlyPrintable(dec) {
			s = string(dec)
		}
	}
	if reHex.MatchString(s) && len(s)%2 == 0 {
		if dec, err := hex.DecodeString(s); err == nil && isMostlyPrintable(dec) {
			s = string(dec)
		}
	}
	return strings.ToLower(s)
}

func hasFilterKey(args map[string]any) bool {
	for k := range args {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "id") || strings.Contains(lk, "where") ||
			strings.Contains(lk, "filter") || lk == "key" {
			return true
		}
	}
	return false
}

// extractAmount finds a financial magnitude and returns integer cents,
// resistant to formatting drift: 5000, "5000", "5,000", "5_000", "5 000",
// "EUR 5000", "5.000,00" all resolve to 500000.
func extractAmount(args map[string]any) (int64, string) {
	currency := ""
	for _, k := range []string{"amount", "total", "value", "sum", "price", "cost", "limit"} {
		for ak, av := range args {
			if strings.ToLower(ak) != k {
				continue
			}
			switch v := av.(type) {
			case float64:
				return int64(v * 100), currency
			case int:
				return int64(v) * 100, currency
			case int64:
				return v * 100, currency
			case string:
				if c := parseMoney(decodeOnly(v)); c >= 0 {
					if cu := detectCurrency(v); cu != "" {
						currency = cu
					}
					return c, currency
				}
			}
		}
	}
	return 0, currency
}

func detectCurrency(s string) string {
	u := strings.ToUpper(s)
	switch {
	case strings.Contains(u, "EUR") || strings.Contains(s, "€"):
		return "EUR"
	case strings.Contains(u, "USD") || strings.Contains(s, "$"):
		return "USD"
	case strings.Contains(u, "GBP") || strings.Contains(s, "£"):
		return "GBP"
	}
	return ""
}

// parseMoney extracts the numeric value from a messy string and returns cents,
// or -1 if no number is present. A '.' or ',' with exactly two trailing digits
// is treated as the decimal point; all other separators are grouping.
func parseMoney(s string) int64 {
	m := reMoney.FindString(s)
	if m == "" {
		return -1
	}
	m = strings.ReplaceAll(m, " ", "")
	m = strings.ReplaceAll(m, "_", "")
	dec := ""
	for i := len(m) - 1; i >= 0; i-- {
		if m[i] == '.' || m[i] == ',' {
			if len(m)-1-i == 2 {
				dec = string(m[i])
			}
			break
		}
	}
	whole := m
	cents := int64(0)
	if dec != "" {
		idx := strings.LastIndex(m, dec)
		whole = stripSeparators(m[:idx])
		if f, err := strconv.Atoi(m[idx+1:]); err == nil {
			cents = int64(f)
		}
	} else {
		whole = stripSeparators(m)
	}
	if whole == "" {
		return -1
	}
	w, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return -1
	}
	return w*100 + cents
}

func stripSeparators(s string) string {
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, ".", "")
	return s
}

func firstStringKey(args map[string]any, keys ...string) string {
	for _, k := range keys {
		for ak, av := range args {
			if strings.ToLower(ak) == k {
				if s, ok := av.(string); ok {
					return s
				}
			}
		}
	}
	return ""
}

func containsAny(h string, subs []string) bool {
	for _, s := range subs {
		if strings.Contains(h, s) {
			return true
		}
	}
	return false
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 32 && c < 127 {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.8
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// String gives a compact human-readable form for logs and audit.
func (a ActionIR) String() string {
	return fmt.Sprintf("op=%s resource=%s scope=%s cents=%d reversible=%t dest=%q",
		a.Op, a.Resource, a.Scope, a.MagnitudeCents, a.Reversible, a.Destination)
}
