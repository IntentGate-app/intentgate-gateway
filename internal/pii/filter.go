package pii

import (
	"errors"
	"fmt"
)

// Action describes what to do when the filter detects PII in a
// response. Configured per-tenant (and optionally per-pattern within a
// tenant) via the customer's Rego policy.
type Action string

const (
	// ActionAllow passes the response through unchanged. Useful as the
	// default when filtering is configured but no patterns match, or
	// when an endpoint is explicitly excluded (e.g. an account-details
	// API that legitimately returns the account holder's own PII).
	ActionAllow Action = "allow"

	// ActionRedact replaces every match with [REDACTED:<class>] and
	// forwards the (modified) response to the agent. The audit row
	// records the count of redactions per class, never the matched
	// values.
	ActionRedact Action = "redact"

	// ActionBlock refuses the response. The gateway returns JSON-RPC
	// error -32015 to the agent; nothing from the upstream response
	// reaches the caller.
	ActionBlock Action = "block"

	// ActionEscalate pauses the response and routes it to a human
	// approver via the existing escalate-to-human pathway (TOTP step-up
	// + approver UI). Useful for low-volume, high-stakes deployments.
	// Not yet implemented in v1 — Filter treats this as Block for now
	// and the integration with the approvals queue lands in week 4.
	ActionEscalate Action = "escalate"
)

// ErrPIIBlocked is returned (wrapped) when the filter blocks a
// response. The wrapped error carries the per-class counts so the
// gateway audit row can record what was found without persisting the
// matched values.
var ErrPIIBlocked = errors.New("pii filter blocked response")

// Config is the per-tenant filter configuration, typically populated
// from the customer's Rego policy at request time.
type Config struct {
	// Enabled is the master switch. When false, the filter is a no-op
	// and ApplyToString returns the input unchanged with ActionAllow.
	Enabled bool

	// Patterns is the set of built-in classes the filter should look
	// for. Empty slice means "all built-ins"; pass an explicit empty
	// slice via &Config{Enabled:true, Patterns: []Class{}} to disable
	// built-ins entirely and rely only on CustomPatterns.
	Patterns []Class

	// CustomPatterns is the customer-declared additional patterns
	// from their Rego policy. Each entry is a regex + a class label
	// the customer chose. Validated at construction (AddCustomPattern
	// rejects ReDoS-prone constructs).
	CustomPatterns []CustomPattern

	// DefaultAction is the action taken when a match occurs and no
	// per-pattern action is configured for that class.
	DefaultAction Action

	// PerPatternAction lets customers override the default for
	// specific classes. E.g. a bank may default to Redact but force
	// Block on IBAN and credit-card classes.
	PerPatternAction map[Class]Action
}

// CustomPattern is one customer-declared additional pattern.
type CustomPattern struct {
	Class Class
	Regex string
}

// Filter is the response-stream PII filter. Construct with NewFilter,
// apply with ApplyToString. Safe for concurrent use after construction.
type Filter struct {
	detector *Detector
	cfg      Config
}

// NewFilter constructs a filter from the given config. Returns an
// error if any custom pattern is invalid (bad regex, ReDoS-prone, or
// missing class label).
func NewFilter(cfg Config) (*Filter, error) {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = ActionRedact
	}

	// Build the detector. nil Patterns means "all built-ins".
	var enabled []Class
	if cfg.Patterns != nil {
		enabled = cfg.Patterns
	}
	d := NewDetector(enabled)

	// Add custom patterns
	for _, cp := range cfg.CustomPatterns {
		if cp.Class == "" {
			return nil, fmt.Errorf("custom pattern with empty class label")
		}
		if cp.Regex == "" {
			return nil, fmt.Errorf("custom pattern %q with empty regex", cp.Class)
		}
		if err := d.AddCustomPattern(cp.Class, cp.Regex); err != nil {
			return nil, fmt.Errorf("custom pattern %q: %w", cp.Class, err)
		}
	}

	return &Filter{detector: d, cfg: cfg}, nil
}

// Decision is the outcome of applying the filter to one input. It
// always reports counts per class (useful for audit even when no
// rewriting happens) and the final action taken.
type Decision struct {
	// Action is the resolved action: Allow, Redact, or Block. Escalate
	// in the config is materialised here as Block for v1; the
	// approvals-integration lands in week 4.
	Action Action

	// Output is the body to forward downstream. For Allow + no
	// matches, it equals the input. For Redact, it's the input with
	// matches replaced by [REDACTED:<class>] tokens. For Block, it's
	// the empty string — caller should not forward Output, should
	// instead return -32015 to the agent.
	Output string

	// Counts maps each PII class to the number of matches found.
	// Safe to persist in audit rows; never contains matched values.
	Counts map[Class]int

	// MatchedClasses lists the distinct classes that triggered. Useful
	// for the audit-row JSON shape.
	MatchedClasses []Class
}

// ApplyToString scans the input for PII according to the filter's
// configuration and returns a Decision describing what to do with it.
//
// If the filter is disabled, returns ActionAllow with the input
// unchanged and no counts.
func (f *Filter) ApplyToString(input string) Decision {
	if f == nil || !f.cfg.Enabled {
		return Decision{
			Action: ActionAllow,
			Output: input,
			Counts: map[Class]int{},
		}
	}

	matches := f.detector.Detect(input)
	counts := CountByClass(matches)

	if len(matches) == 0 {
		return Decision{
			Action: ActionAllow,
			Output: input,
			Counts: counts,
		}
	}

	// Resolve action. Per-pattern overrides default. If multiple
	// matched classes have conflicting actions, the most restrictive
	// wins: Block > Escalate > Redact > Allow.
	action := f.resolveAction(matches)

	matchedClasses := distinctClasses(matches)

	switch action {
	case ActionBlock, ActionEscalate:
		// In v1 Escalate is materialised as Block until the
		// approvals-queue integration lands in week 4. The Action in
		// the Decision still reports Escalate so the audit row is
		// accurate; only the runtime behaviour is identical to Block.
		return Decision{
			Action:         action,
			Output:         "",
			Counts:         counts,
			MatchedClasses: matchedClasses,
		}
	case ActionRedact:
		out, _ := Redact(input, matches)
		return Decision{
			Action:         ActionRedact,
			Output:         out,
			Counts:         counts,
			MatchedClasses: matchedClasses,
		}
	default:
		// ActionAllow with matches present — odd config, but log it
		// and pass through.
		return Decision{
			Action:         ActionAllow,
			Output:         input,
			Counts:         counts,
			MatchedClasses: matchedClasses,
		}
	}
}

// resolveAction picks the action to take when matches are present.
// Most-restrictive wins so a single Block override beats a permissive
// default.
func (f *Filter) resolveAction(matches []Match) Action {
	worst := f.cfg.DefaultAction
	for _, m := range matches {
		if override, ok := f.cfg.PerPatternAction[m.Class]; ok {
			worst = mostRestrictive(worst, override)
		}
	}
	return worst
}

func mostRestrictive(a, b Action) Action {
	rank := func(a Action) int {
		switch a {
		case ActionBlock:
			return 4
		case ActionEscalate:
			return 3
		case ActionRedact:
			return 2
		case ActionAllow:
			return 1
		default:
			return 0
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func distinctClasses(matches []Match) []Class {
	seen := make(map[Class]bool)
	var out []Class
	for _, m := range matches {
		if !seen[m.Class] {
			seen[m.Class] = true
			out = append(out, m.Class)
		}
	}
	return out
}
