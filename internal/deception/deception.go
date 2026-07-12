// Package deception is the inline engagement detector for the agent
// deception fabric. It recognises, on the hot path, when an agent call
// touches a decoy: a honey-tool advertised but in no token's scope, a
// decoy capability token, a decoy zone/service, or a planted
// honey-credential. A decoy is something no legitimate agent, task, or
// token ever has a reason to touch, so a single match is proof of
// compromise, not a probabilistic anomaly.
//
//	no match -> pass (fall through to the rest of the pipeline)
//	match    -> trip (contain per the decoy's on-trip setting)
//
// The detector is deterministic and stateless: the decoy set lives behind
// the Registry seam. Today that is an embedded, config-loaded set
// (StaticRegistry); later a live sync from the console's decoy store. This
// mirrors how refverify started with a static vendor master before a
// system-of-record connector.
//
// Containment (kill switch + token revoke) and recording the trip are the
// caller's job — this package decides *whether* a call is a trip and what
// the response should be, exactly as refverify decides a verdict without
// itself pausing the request.
package deception

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// Kind names what a decoy is seeded into.
type Kind string

const (
	HoneyTool       Kind = "honey_tool"
	HoneyCredential Kind = "honey_credential"
	HoneyRecord     Kind = "honey_record"
	DecoyToken      Kind = "decoy_token"
	DecoyZone       Kind = "decoy_zone"
	InjectionCanary Kind = "injection_canary"
	Breadcrumb      Kind = "breadcrumb"
)

// OnTrip is what a trip triggers. Contain == kill switch + token revoke.
type OnTrip string

const (
	OnTripAlert   OnTrip = "alert"
	OnTripHold    OnTrip = "hold"
	OnTripContain OnTrip = "contain"
)

// Severity and Action mirror the console's trip record so a recorded trip
// reads identically whether it came from here or was simulated.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
)

type Action string

const (
	ActionContained Action = "contained"
	ActionHeld      Action = "held"
	ActionAlerted   Action = "alerted"
)

// Decoy is one live decoy the detector watches for. Key is the value a
// call is matched against, scoped by Kind: a tool name for HoneyTool, a
// token id for DecoyToken, a zone/service name for DecoyZone, a credential
// id for HoneyCredential.
type Decoy struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   Kind   `json:"kind"`
	Key    string `json:"key"`
	Pillar string `json:"pillar"`
	OnTrip OnTrip `json:"on_trip"`
}

var reSpace = regexp.MustCompile(`\s+`)

// normTool/normZone fold case and whitespace so a decoy match is
// drift-resistant. Token and credential ids match exactly.
func norm(s string) string {
	return strings.ToLower(reSpace.ReplaceAllString(strings.TrimSpace(s), ""))
}

// Registry is the seam to the set of live decoys. Match returns the decoy
// a call touched, if any. Implementations must be safe for concurrent use.
type Registry interface {
	Match(in Input) (Decoy, bool)
}

// Input is the slice of a call the detector inspects. Any field may be
// empty; the detector checks each populated dimension against the
// matching decoy kind.
type Input struct {
	Tool         string // tool being called
	TokenID      string // capability token id (JTI) presented
	Zone         string // zone or service being reached
	CredentialID string // brokered credential id being used
}

// StaticRegistry is an in-memory Registry indexed by kind. It is the
// embedded decoy set used before a live sync from the console decoy store.
type StaticRegistry struct {
	tools  map[string]Decoy
	tokens map[string]Decoy
	zones  map[string]Decoy
	creds  map[string]Decoy
}

// NewStaticRegistry indexes the given decoys by kind. Only decoy kinds the
// gateway can observe inline are indexed (honey-tool, decoy-token,
// decoy-zone, honey-credential); record- and content-level decoys are
// matched elsewhere and are ignored here.
func NewStaticRegistry(decoys []Decoy) *StaticRegistry {
	r := &StaticRegistry{
		tools:  map[string]Decoy{},
		tokens: map[string]Decoy{},
		zones:  map[string]Decoy{},
		creds:  map[string]Decoy{},
	}
	for _, d := range decoys {
		if d.Key == "" {
			continue
		}
		switch d.Kind {
		case HoneyTool:
			r.tools[norm(d.Key)] = d
		case DecoyToken:
			r.tokens[d.Key] = d
		case DecoyZone:
			r.zones[norm(d.Key)] = d
		case HoneyCredential:
			r.creds[d.Key] = d
		}
	}
	return r
}

// Match implements Registry. Dimensions are checked in a fixed order so
// the verdict is deterministic when a call somehow touches more than one
// decoy: token, then tool, then credential, then zone.
func (r *StaticRegistry) Match(in Input) (Decoy, bool) {
	if in.TokenID != "" {
		if d, ok := r.tokens[in.TokenID]; ok {
			return d, true
		}
	}
	if in.Tool != "" {
		if d, ok := r.tools[norm(in.Tool)]; ok {
			return d, true
		}
	}
	if in.CredentialID != "" {
		if d, ok := r.creds[in.CredentialID]; ok {
			return d, true
		}
	}
	if in.Zone != "" {
		if d, ok := r.zones[norm(in.Zone)]; ok {
			return d, true
		}
	}
	return Decoy{}, false
}

// Detector applies deception detection. Stateless and safe for concurrent
// use; the decoy set lives behind the Registry.
type Detector struct {
	reg Registry
}

// New returns a Detector over the given registry. A nil registry yields a
// detector that never trips, so deception is simply off until decoys are
// configured.
func New(reg Registry) *Detector {
	return &Detector{reg: reg}
}

// Result is the detector's verdict.
type Result struct {
	// Tripped is true when the call touched a decoy.
	Tripped bool
	// Decoy is the decoy that was touched (zero value when not tripped).
	Decoy Decoy
	// Severity and Action describe the response, derived from the decoy's
	// on-trip setting, and match the console's trip record shape.
	Severity Severity
	Action   Action
	// Contain is true when the caller should fire the kill switch and
	// revoke the token, i.e. on-trip == contain.
	Contain bool
	// Reason is an operator-readable summary of the trip.
	Reason string
}

// Check reports whether a call touched a decoy and, if so, how to respond.
// A non-tripped result is the common case and is cheap: one map probe per
// populated input dimension.
func (d *Detector) Check(in Input) Result {
	if d == nil || d.reg == nil {
		return Result{}
	}
	decoy, ok := d.reg.Match(in)
	if !ok {
		return Result{}
	}
	sev, act, contain := outcome(decoy.OnTrip)
	return Result{
		Tripped:  true,
		Decoy:    decoy,
		Severity: sev,
		Action:   act,
		Contain:  contain,
		Reason:   reasonFor(decoy, act),
	}
}

// outcome maps a decoy's on-trip setting to the trip severity, action, and
// whether to contain inline.
func outcome(o OnTrip) (Severity, Action, bool) {
	switch o {
	case OnTripContain:
		return SevCritical, ActionContained, true
	case OnTripHold:
		return SevHigh, ActionHeld, false
	default:
		return SevMedium, ActionAlerted, false
	}
}

func reasonFor(d Decoy, a Action) string {
	switch a {
	case ActionContained:
		return "agent touched decoy " + d.Name + ", in no token's scope; kill switch fired, token revoked"
	case ActionHeld:
		return "agent acted on decoy " + d.Name + "; held for the incident responder"
	default:
		return "agent acted on decoy " + d.Name + "; flagged and alerted"
	}
}

// LoadConfigFile reads a decoy-set JSON file of shape
//
//	{"decoys":[{"id":"...","name":"...","kind":"honey_tool","key":"admin_payments","on_trip":"contain"}]}
//
// and returns the decoys. This is the embedded set the gateway watches for
// before a live sync from the console decoy store is wired in.
func LoadConfigFile(path string) ([]Decoy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		Decoys []Decoy `json:"decoys"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	return file.Decoys, nil
}
