// Package pii implements PII detection and filtering for IntentGate's
// LLM02 (Sensitive Information Disclosure) defense.
//
// # Overview
//
// LLM02 closes the procurement-blocking gap for EU regulated buyers:
// when an agent's response stream contains PII the user didn't ask
// for, the existing five checks have no opinion (they evaluated the
// request, not the response). This package adds the sixth checkpoint:
// after the upstream tool server returns its response, before the
// gateway forwards it to the agent, the response stream is scanned
// for PII matching customer-declared classes; the configured action
// (block / redact / escalate) is taken; an audit row is emitted that
// counts matches per class (never logs the matched values themselves).
//
// # Design decisions
//
// Pinned in memos/llm02-pii-filter-design.md:
//
//   - Response-side only. Request-side filtering would block legitimate
//     reads.
//   - Pattern-based Go regex with checksum validation where applicable
//     (IBAN mod-97, BSN mod-11, credit card Luhn).
//   - Bundled patterns are ported from Microsoft Presidio's high-precision
//     set plus EU additions (BSN, EU VAT) Presidio does not ship by
//     default.
//   - Customer-extensible: customers declare additional patterns in
//     their Rego policy; the detector reads them at request time.
//   - Audit chain row contains pattern-class counts only, never the
//     matched substrings. PII never reaches the audit table.
//   - Three actions: block (return -32015), redact (replace with
//     [REDACTED:<class>]), escalate (route to human approver).
//   - Performance: ≤ 1 ms p50, ≤ 5 ms p99 per response. Achievable
//     because Go regex with pre-compiled patterns runs at GB/s.
//
// # Error code
//
// PII filter blocks return JSON-RPC error -32015 (matches the
// AAI03 provenance pattern of typed errors in the -32010..-32020
// range, one error code per pipeline check).
package pii

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Class identifies a PII pattern category. The string value is what
// appears in audit rows (counts per class) and in [REDACTED:<class>]
// markers.
type Class string

// Built-in pattern classes. Each has:
//   - A precision target documented in the design doc
//   - A checksum / validation function where the format admits one
//   - A regex pre-compiled at package init for hot-path performance
const (
	ClassEmail      Class = "email"
	ClassPhoneIntl  Class = "phone_intl"
	ClassIBAN       Class = "iban"
	ClassBSN        Class = "bsn"
	ClassCreditCard Class = "credit_card"
	ClassSSNUS      Class = "ssn_us"
	ClassVATEU      Class = "vat_eu"
	ClassIPv4       Class = "ipv4"
	ClassIPv6       Class = "ipv6"
)

// Match represents a single PII detection in a string. Offset and End
// are byte indices into the original input. Value is the matched
// substring; callers MUST NOT include Value in audit rows or other
// persistent stores — it is provided only so a filter caller can
// perform redaction.
type Match struct {
	Class  Class
	Value  string
	Offset int
	End    int
}

// Pattern bundles a regex with an optional checksum validator. The
// validator returns true if the match is genuine (e.g. IBAN passes
// mod-97); false if it's a false positive that happened to match the
// regex (e.g. a random 18-digit number that doesn't pass Luhn).
type Pattern struct {
	Class    Class
	Regex    *regexp.Regexp
	Validate func(match string) bool // nil means accept all regex matches
}

// Detector holds a set of compiled patterns and scans inputs for
// matches. Detectors are safe for concurrent use after construction.
type Detector struct {
	patterns []Pattern
}

// NewDetector returns a detector with the requested built-in classes
// enabled. Pass nil to enable all built-in classes.
//
// To add customer-extensible patterns (declared in Rego), use
// AddCustomPattern.
func NewDetector(enabled []Class) *Detector {
	d := &Detector{}
	all := builtinPatterns()

	if enabled == nil {
		// Enable all built-ins by default
		d.patterns = all
		return d
	}

	want := make(map[Class]bool, len(enabled))
	for _, c := range enabled {
		want[c] = true
	}
	for _, p := range all {
		if want[p.Class] {
			d.patterns = append(d.patterns, p)
		}
	}
	return d
}

// AddCustomPattern registers a customer-declared pattern. The class
// name will appear in audit rows; the regex is the matcher. Custom
// patterns do not get checksum validation (customers declare format,
// not validation).
//
// Returns an error if the regex doesn't compile or contains a
// potentially-catastrophic backtracking construct.
func (d *Detector) AddCustomPattern(class Class, pattern string) error {
	// Reject patterns with nested quantifiers — common source of ReDoS.
	// This is a conservative heuristic, not a full Spencer-Smith analysis.
	if hasNestedQuantifier(pattern) {
		return fmt.Errorf("pattern %q rejected: nested quantifier (potential ReDoS)", pattern)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("pattern %q: %w", pattern, err)
	}
	d.patterns = append(d.patterns, Pattern{Class: class, Regex: re})
	return nil
}

// Detect scans the input string for matches against every enabled
// pattern. Matches are returned in input-order (ascending offset).
// The matched substring is included so the caller can perform
// redaction; the caller MUST NOT persist these values.
//
// Overlapping matches are coalesced: when two matches cover the same
// (or nested) byte range, the higher-priority class wins. Priority
// is "pattern with a validator > pattern without a validator"
// (a validator-having class like BSN with mod-11 elf-proef is more
// specific than a generic regex like phone_intl that happens to
// match 9 digits). Ties — same validator-having-ness — break in
// pattern-registration order. This prevents the cosmetic artifact
// where Redact interleaves multiple markers over the same digits.
func (d *Detector) Detect(input string) []Match {
	type rawMatch struct {
		Match
		hasValidator bool
		patternIdx   int
	}
	var raw []rawMatch
	for i, p := range d.patterns {
		idx := p.Regex.FindAllStringIndex(input, -1)
		for _, span := range idx {
			val := input[span[0]:span[1]]
			if p.Validate != nil && !p.Validate(val) {
				continue
			}
			raw = append(raw, rawMatch{
				Match: Match{
					Class:  p.Class,
					Value:  val,
					Offset: span[0],
					End:    span[1],
				},
				hasValidator: p.Validate != nil,
				patternIdx:   i,
			})
		}
	}

	// Sort by offset ascending; within the same range, validator-having
	// classes first; then earlier-registered pattern. This ordering
	// makes the coalesce loop O(n) and deterministic.
	for i := 0; i < len(raw); i++ {
		for j := i + 1; j < len(raw); j++ {
			a, b := raw[i], raw[j]
			swap := false
			if a.Offset != b.Offset {
				swap = a.Offset > b.Offset
			} else if a.End != b.End {
				swap = a.End < b.End // longer first
			} else if a.hasValidator != b.hasValidator {
				swap = !a.hasValidator
			} else {
				swap = a.patternIdx > b.patternIdx
			}
			if swap {
				raw[i], raw[j] = raw[j], raw[i]
			}
		}
	}

	// Coalesce: drop matches that are contained within (or identical
	// to) an already-kept match. "Contained" means the byte range is
	// a subset; with the sort above the kept match is always seen
	// first, so we just track the rightmost kept End and skip any
	// match whose End is <= that.
	var matches []Match
	keptEnd := -1
	for _, m := range raw {
		if m.Offset < keptEnd && m.End <= keptEnd {
			// Fully contained in a higher-priority kept match.
			continue
		}
		matches = append(matches, m.Match)
		if m.End > keptEnd {
			keptEnd = m.End
		}
	}
	return matches
}

// Redact returns a copy of input with each match replaced by
// [REDACTED:<class>]. Counts per class are returned for audit logging
// — these counts are safe to persist (no PII values).
//
// If matches is nil or empty, returns (input, empty map).
func Redact(input string, matches []Match) (string, map[Class]int) {
	counts := make(map[Class]int)
	if len(matches) == 0 {
		return input, counts
	}

	// Sort descending by offset so we can replace in place without
	// invalidating earlier offsets.
	sorted := make([]Match, len(matches))
	copy(sorted, matches)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Offset > sorted[i].Offset {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	out := input
	for _, m := range sorted {
		token := fmt.Sprintf("[REDACTED:%s]", m.Class)
		out = out[:m.Offset] + token + out[m.End:]
		counts[m.Class]++
	}
	return out, counts
}

// CountByClass returns a class → count map for the given matches.
// Useful for audit rows when the caller is NOT redacting (e.g.
// block decisions) but still wants to log what was found.
func CountByClass(matches []Match) map[Class]int {
	counts := make(map[Class]int)
	for _, m := range matches {
		counts[m.Class]++
	}
	return counts
}

// ---------------------------------------------------------------------
// Built-in patterns
// ---------------------------------------------------------------------

var (
	// Email — RFC 5322-lite. Conservative; rejects exotic legal forms
	// (quoted locals, IP-literal domains) to keep false positives low.
	emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	// E.164 + common national formats. Requires at least 8 digits.
	phoneRe = regexp.MustCompile(`\+?\d{1,3}[\s.\-]?\(?\d{1,4}\)?[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}\b`)

	// IBAN — country code + 2 check digits + up to 30 alphanumerics.
	// Validator runs mod-97 below.
	ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}[\s]?(?:[A-Z0-9]{4}[\s]?){3,7}[A-Z0-9]{1,4}\b`)

	// BSN — 8 or 9 digits with mod-11 checksum (validator below).
	bsnRe = regexp.MustCompile(`\b\d{9}\b`)

	// Credit card — 13–19 digits with optional spaces or dashes.
	// Validator runs Luhn below.
	ccRe = regexp.MustCompile(`\b(?:\d[\s\-]?){12,18}\d\b`)

	// US SSN — XXX-XX-XXXX format. RE2 has no lookahead, so the
	// "invalid prefix" rules (first group not 000/666/9XX, middle not
	// 00, last not 0000) are enforced in validSSN below.
	ssnUSRe = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// EU VAT — country code + 8–12 alphanumerics.
	vatEURe = regexp.MustCompile(`\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|GB|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI)[0-9A-Z]{8,12}\b`)

	// IPv4 — dotted-quad with each octet 0..255.
	ipv4Re = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`)

	// IPv6 — covers the common forms (full, compressed, mixed).
	ipv6Re = regexp.MustCompile(`\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}\b|\b::[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){0,5}\b`)
)

func builtinPatterns() []Pattern {
	// PII-class patterns first (validator-having classes leftmost so
	// the Detect coalesce step prefers them on equal-range hits).
	out := []Pattern{
		{Class: ClassIBAN, Regex: ibanRe, Validate: validIBAN},
		{Class: ClassBSN, Regex: bsnRe, Validate: validBSN},
		{Class: ClassCreditCard, Regex: ccRe, Validate: validLuhn},
		{Class: ClassSSNUS, Regex: ssnUSRe, Validate: validSSN},
		{Class: ClassEmail, Regex: emailRe},
		{Class: ClassPhoneIntl, Regex: phoneRe},
		{Class: ClassVATEU, Regex: vatEURe},
		{Class: ClassIPv4, Regex: ipv4Re},
		{Class: ClassIPv6, Regex: ipv6Re},
	}
	// Credential-class patterns appended in their own priority order.
	// See credentials.go::credentialPatterns().
	out = append(out, credentialPatterns()...)
	return out
}

// ---------------------------------------------------------------------
// Checksum validators
// ---------------------------------------------------------------------

// validIBAN runs the ISO 13616 mod-97 check on the candidate string.
// Spec: move first 4 chars to end, convert letters (A=10..Z=35) to
// digits, treat result as a big integer, check mod 97 == 1.
func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	moved := s[4:] + s[:4]
	var num strings.Builder
	for _, r := range moved {
		switch {
		case r >= '0' && r <= '9':
			num.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			num.WriteString(strconv.Itoa(int(r) - 'A' + 10))
		default:
			return false
		}
	}
	// mod-97 over a potentially-large integer — compute incrementally
	rem := 0
	for _, c := range num.String() {
		rem = (rem*10 + int(c-'0')) % 97
	}
	return rem == 1
}

// validBSN runs the Dutch BSN mod-11 checksum:
//
//	(9*d1 + 8*d2 + 7*d3 + 6*d4 + 5*d5 + 4*d6 + 3*d7 + 2*d8 + -1*d9) mod 11 == 0
//
// Modern BSN is always 9 digits. The historic 8-digit format (pre-2007)
// is intentionally not supported — accepting 8-digit numbers as BSN
// candidates would produce too many false positives on ordinary
// identifiers (timestamps, record IDs, phone fragments).
func validBSN(s string) bool {
	if len(s) != 9 {
		return false
	}
	weights := []int{9, 8, 7, 6, 5, 4, 3, 2, -1}
	sum := 0
	for i, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		sum += int(c-'0') * weights[i]
	}
	return sum%11 == 0
}

// validSSN enforces the SSA's rules on which SSN prefixes are valid:
//
//   - First group (area number) must not be 000, 666, or 900–999
//   - Middle group (group number) must not be 00
//   - Last group (serial number) must not be 0000
//
// RE2 has no negative lookahead, so this is enforced in Go after
// the regex matches the structural format.
func validSSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 || len(parts[0]) != 3 || len(parts[1]) != 2 || len(parts[2]) != 4 {
		return false
	}
	a, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	if a == 0 || a == 666 || a >= 900 {
		return false
	}
	if parts[1] == "00" {
		return false
	}
	if parts[2] == "0000" {
		return false
	}
	return true
}

// validLuhn runs the Luhn (mod-10) check on a credit-card candidate.
// Strips spaces and dashes first.
func validLuhn(s string) bool {
	stripped := strings.NewReplacer(" ", "", "-", "").Replace(s)
	n := len(stripped)
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		c := stripped[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

// hasNestedQuantifier flags patterns like (a+)+ or (a*)* that can
// cause catastrophic backtracking in non-RE2 engines. Go's regexp is
// RE2 (linear time), so these can't actually backtrack catastrophically
// — but we reject them anyway to keep customer patterns clean and to
// avoid surprises if the engine is ever swapped (e.g. for a
// PCRE-compatible custom-pattern path).
//
// Algorithm: track a stack of groups; each frame remembers whether
// a quantifier was seen inside that group. When the group closes and
// is followed by another quantifier, that's a nested-quantifier
// pattern — return true.
func hasNestedQuantifier(pattern string) bool {
	type frame struct {
		sawInnerQuant bool
	}
	var stack []frame

	isQuant := func(b byte) bool {
		return b == '+' || b == '*' || b == '?' || b == '{'
	}

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			// Skip escaped character
			i++
			continue
		case '(':
			stack = append(stack, frame{})
		case ')':
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			// If this closed group is followed by a quantifier AND
			// contained an inner quantifier, it's a nested-quantifier
			// construct (e.g. (a+)+, (a*)*, ([abc]+)+).
			if i+1 < len(pattern) && isQuant(pattern[i+1]) {
				if top.sawInnerQuant {
					return true
				}
			}
		case '+', '*', '?':
			// Quantifier inside the currently-open group
			if len(stack) > 0 {
				stack[len(stack)-1].sawInnerQuant = true
			}
		}
	}
	return false
}

// sortByOffset orders matches in ascending input position. Stable sort
// not required since offsets are unique per pattern; if two patterns
// match the same exact bytes we keep insertion order.
func sortByOffset(matches []Match) {
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].Offset < matches[i].Offset {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
}
