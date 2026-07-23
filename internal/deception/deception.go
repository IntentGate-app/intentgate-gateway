// Package deception is the inline engagement detector for the agent
// deception fabric. It recognises, on the hot path, when an agent call
// touches a decoy: a honey-tool advertised but in no token's scope, a
// decoy capability token, a decoy zone/service, a planted honey-credential
// or honey-record value, or an injection-canary marker the agent carries
// into its own output after obeying injected content. A decoy is something
// no legitimate agent, task, or token ever has a reason to touch, so a
// single match is proof of compromise, not a probabilistic anomaly.
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
	"sort"
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
	// OnTripSandbox does not contain. The gateway returns the decoy's
	// synthetic response and lets the agent keep acting, capturing the
	// whole tool chain as a stateful engagement. It is the high-interaction
	// counterpart to the tripwire modes above: a contain trip proves
	// compromise in one touch, a sandbox trip additionally records what the
	// agent tried to do once it believed it had succeeded.
	OnTripSandbox OnTrip = "sandbox"
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
	// Synthetic is the fake payload returned to the agent when OnTrip is
	// sandbox. It is operator-authored believable content (a fake supplier
	// record, a fake secret) whose only job is to keep the agent acting so
	// its next move is observed. Empty for non-sandbox decoys.
	Synthetic string `json:"synthetic,omitempty"`
	// ResponseActions are extra side-effects to run on a trip, on top of the
	// on-trip posture: "notify_soc" (emit to the webhook sink),
	// "capture_session" (retain the touching call's payload). Empty means
	// none beyond the posture. Unknown values are ignored.
	ResponseActions []string `json:"response_actions,omitempty"`
}

// Response action identifiers carried on a decoy. Kept as plain strings on
// the wire so the console owns the vocabulary; the handler matches these.
const (
	ActionNotifySOC       = "notify_soc"
	ActionCaptureSession  = "capture_session"
)

// HasResponseAction reports whether the decoy requests the named extra
// side-effect on a trip.
func (d Decoy) HasResponseAction(name string) bool {
	for _, a := range d.ResponseActions {
		if a == name {
			return true
		}
	}
	return false
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
	Tool         string   // tool being called
	TokenID      string   // capability token id (JTI) presented
	Zone         string   // zone or service being reached
	CredentialID string   // brokered credential id being used
	Values       []string // argument values on the call (payee ids, keys, ...)
	// Content is free text the agent itself produced: the serialised
	// arguments of a tool call, or an outbound reply. It is scanned for a
	// planted injection-canary marker. A canary is a unique string seeded
	// into content an agent may retrieve; a prompt injection that hijacks
	// the agent gets the agent to carry that marker into what it does next.
	// Seeing the marker in the agent's own output is proof the injection was
	// obeyed, so it is caught here rather than by trying to read intent.
	Content string
}

// ValuesFromArgs flattens a tool call's arguments into the string values
// the detector matches against honey-record and honey-credential decoys.
// It walks nested maps and slices so a payee id or a leaked key is caught
// wherever it sits in the arguments.
func ValuesFromArgs(args map[string]any) []string {
	out := make([]string, 0, len(args))
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if t != "" {
				out = append(out, t)
			}
		case map[string]any:
			for _, vv := range t {
				walk(vv)
			}
		case []any:
			for _, vv := range t {
				walk(vv)
			}
		}
	}
	for _, v := range args {
		walk(v)
	}
	return out
}

// ContentFromArgs serialises a tool call's arguments to a single string for
// injection-canary scanning. Unlike ValuesFromArgs, which pulls out leaf
// string values, this keeps the whole argument blob so a marker embedded
// anywhere in the structure is scanned. Best-effort: an unmarshalable value
// yields an empty string, in which case leaf-value scanning still applies.
func ContentFromArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil {
		return ""
	}
	return string(b)
}

// canary is one injection-canary marker: the normalised marker string and
// the decoy it belongs to. Markers are matched as substrings of the agent's
// own output, not by exact key, so a marker carried inside a larger value is
// still caught.
type canary struct {
	marker string
	decoy  Decoy
}

// StaticRegistry is an in-memory Registry indexed by kind. It is the
// embedded decoy set used before a live sync from the console decoy store.
type StaticRegistry struct {
	tools    map[string]Decoy
	tokens   map[string]Decoy
	zones    map[string]Decoy
	creds    map[string]Decoy
	values   map[string]Decoy // honey-record / leaked-key values seen in args
	canaries []canary         // injection-canary markers, scanned as substrings
}

// NewStaticRegistry indexes the given decoys by kind. Exact-match kinds
// (honey-tool, decoy-token, decoy-zone, honey-credential, honey-record) go
// into their maps; the injection-canary kind is a content-level marker and
// is scanned as a substring of the agent's own output. Breadcrumbs are lures
// with no trip of their own and are not indexed.
func NewStaticRegistry(decoys []Decoy) *StaticRegistry {
	r := &StaticRegistry{
		tools:  map[string]Decoy{},
		tokens: map[string]Decoy{},
		zones:  map[string]Decoy{},
		creds:  map[string]Decoy{},
		values: map[string]Decoy{},
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
			// A leaked decoy key can be presented as a brokered credential
			// id or passed as a call argument, so index it both ways.
			r.creds[d.Key] = d
			r.values[norm(d.Key)] = d
		case HoneyRecord:
			// A seeded fake value (a payee id, a record key) is caught when
			// the agent acts on it, i.e. passes it as a call argument.
			r.values[norm(d.Key)] = d
		case InjectionCanary:
			if m := norm(d.Key); m != "" {
				r.canaries = append(r.canaries, canary{marker: m, decoy: d})
			}
		}
	}
	// Deterministic scan order when a call somehow carries more than one
	// marker: longest marker first (most specific), then lexical.
	sort.Slice(r.canaries, func(i, j int) bool {
		if len(r.canaries[i].marker) != len(r.canaries[j].marker) {
			return len(r.canaries[i].marker) > len(r.canaries[j].marker)
		}
		return r.canaries[i].marker < r.canaries[j].marker
	})
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
	for _, v := range in.Values {
		if v == "" {
			continue
		}
		if d, ok := r.values[norm(v)]; ok {
			return d, true
		}
	}
	if in.Zone != "" {
		if d, ok := r.zones[norm(in.Zone)]; ok {
			return d, true
		}
	}
	// Injection-canary markers are scanned last, as substrings of the
	// agent's own output: its serialised call arguments and any outbound
	// content. norm folds case and strips whitespace, so a marker survives
	// reformatting or being embedded in a larger string.
	if len(r.canaries) > 0 {
		hay := norm(in.Content)
		vals := make([]string, 0, len(in.Values))
		for _, v := range in.Values {
			if v != "" {
				vals = append(vals, norm(v))
			}
		}
		for _, c := range r.canaries {
			if hay != "" && strings.Contains(hay, c.marker) {
				return c.decoy, true
			}
			for _, v := range vals {
				if strings.Contains(v, c.marker) {
					return c.decoy, true
				}
			}
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
	// Sandbox is true when on-trip == sandbox: the caller must NOT block or
	// contain, must return Synthetic to the agent as a successful result,
	// and must record the interaction as an engagement action so the chain
	// is captured.
	Sandbox bool
	// Synthetic is the fake payload to return to the agent in sandbox mode.
	Synthetic string
	// ResponseActions are the extra side-effects the touched decoy requests
	// on a trip (notify_soc, capture_session), copied from the decoy so the
	// handler can act on and record them.
	ResponseActions []string
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
	sandbox := decoy.OnTrip == OnTripSandbox
	return Result{
		Tripped:         true,
		Decoy:           decoy,
		Severity:        sev,
		Action:          act,
		Contain:         contain,
		Sandbox:         sandbox,
		Synthetic:       decoy.Synthetic,
		ResponseActions: decoy.ResponseActions,
		Reason:          reasonFor(decoy, act),
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
	case OnTripSandbox:
		// Sandbox does not contain: the agent is allowed to keep acting so
		// its chain is observed. It is a critical signal all the same — the
		// touch itself is deterministic proof of compromise.
		return SevCritical, ActionAlerted, false
	default:
		return SevMedium, ActionAlerted, false
	}
}

func reasonFor(d Decoy, a Action) string {
	if d.OnTrip == OnTripSandbox {
		return "agent entered sandbox decoy " + d.Name + "; served synthetic response, chain being captured"
	}
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
