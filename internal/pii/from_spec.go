package pii

// FilterSpec is the policy-supplied PII filter spec, decoupled from
// the policy package so the pii package has no upstream dependency.
// The handler converts a policy.PIIFilterSpec into this struct.
type FilterSpec struct {
	Enabled          bool
	Patterns         []string
	DefaultAction    string
	PerPatternAction map[string]string
	CustomPatterns   []FilterSpecCustomPattern
}

// FilterSpecCustomPattern is one customer-declared additional pattern.
type FilterSpecCustomPattern struct {
	Class string
	Regex string
}

// NewFilterFromSpec converts a policy-supplied spec (typically from a
// Rego decision) into a runtime Filter. Returns an error if any custom
// pattern is invalid (ReDoS-prone or bad regex).
//
// Unknown pattern names in spec.Patterns are silently skipped — the
// policy author may have referenced a class the current build doesn't
// ship; we'd rather degrade gracefully than crash the request.
func NewFilterFromSpec(spec FilterSpec) (*Filter, error) {
	if !spec.Enabled {
		return NewFilter(Config{Enabled: false})
	}

	cfg := Config{
		Enabled: true,
	}

	// Resolve enabled classes. Unknown classes are skipped.
	if len(spec.Patterns) > 0 {
		known := knownClasses()
		for _, p := range spec.Patterns {
			c := Class(p)
			if known[c] {
				cfg.Patterns = append(cfg.Patterns, c)
			}
		}
		// If every class was unknown, leave cfg.Patterns empty so the
		// detector enables all built-ins (safer default than nothing).
		if len(cfg.Patterns) == 0 {
			cfg.Patterns = nil
		}
	}

	// Default action
	switch spec.DefaultAction {
	case "allow":
		cfg.DefaultAction = ActionAllow
	case "redact", "":
		cfg.DefaultAction = ActionRedact
	case "block":
		cfg.DefaultAction = ActionBlock
	case "escalate":
		cfg.DefaultAction = ActionEscalate
	default:
		cfg.DefaultAction = ActionRedact // safe default for unknown
	}

	// Per-pattern overrides
	if len(spec.PerPatternAction) > 0 {
		cfg.PerPatternAction = make(map[Class]Action, len(spec.PerPatternAction))
		for class, action := range spec.PerPatternAction {
			var a Action
			switch action {
			case "allow":
				a = ActionAllow
			case "redact":
				a = ActionRedact
			case "block":
				a = ActionBlock
			case "escalate":
				a = ActionEscalate
			default:
				continue // skip unknown actions
			}
			cfg.PerPatternAction[Class(class)] = a
		}
	}

	// Custom patterns
	if len(spec.CustomPatterns) > 0 {
		cfg.CustomPatterns = make([]CustomPattern, 0, len(spec.CustomPatterns))
		for _, cp := range spec.CustomPatterns {
			cfg.CustomPatterns = append(cfg.CustomPatterns, CustomPattern{
				Class: Class(cp.Class),
				Regex: cp.Regex,
			})
		}
	}

	return NewFilter(cfg)
}

// knownClasses returns the set of built-in pattern classes for fast
// membership checks. Built once per call but the set is small so the
// allocation cost is irrelevant on a request-hot-path.
func knownClasses() map[Class]bool {
	return map[Class]bool{
		// PII classes
		ClassEmail:      true,
		ClassPhoneIntl:  true,
		ClassIBAN:       true,
		ClassBSN:        true,
		ClassCreditCard: true,
		ClassSSNUS:      true,
		ClassVATEU:      true,
		ClassIPv4:       true,
		ClassIPv6:       true,
		// Credential classes (RIP Week 2). Same engine, same actions —
		// policy authors enable them by name in the patterns list just
		// like PII classes. Defaults to block-by-default are encoded in
		// the policy / static config, not here; this map only answers
		// "is this a recognised built-in class?".
		ClassAWSAccessKey:      true,
		ClassAWSSecretKey:      true,
		ClassGitHubPAT:         true,
		ClassJWT:               true,
		ClassOAuthBearer:       true,
		ClassSSHPrivateKey:     true,
		ClassGCPServiceAccount: true,
		ClassGenericAPIKey:     true,
	}
}
