// Package audit emits structured events for every authorization
// decision the gateway makes. One event per /v1/mcp tools/call: the
// decision (allow or block), which check fired (capability, intent,
// policy, or budget), the actor (agent), the resource (tool), and the
// reason — everything the SOC analyst needs to reconstruct what the
// agent did and why the gateway responded the way it did.
//
// # Event shape
//
// The Event struct is a lightweight OCSF-lite shape: a flat JSON
// document the customer's SIEM can ingest without a custom mapper.
// Field names are lowercase_underscore so they merge cleanly into ECS
// (Elastic Common Schema), CIM (Splunk), and OCSF without a renaming
// step. Mapping to full OCSF (with category_uid, class_uid, etc.)
// can be done in a downstream parser if/when a customer needs it.
//
// # Emitters
//
// Two implementations ship in v0.1:
//
//   - [StdoutEmitter] — writes one JSON line per event to stdout.
//     The default. Operators tail the gateway's logs (or pipe through
//     vector / fluent-bit / promtail) and route into their SIEM.
//   - [NullEmitter] — drops all events. Used in tests and when audit
//     emission is intentionally disabled.
//
// Future emitters: rotated JSONL files, Kafka, OTLP. Behind the same
// [Emitter] interface so swapping is one config change.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Decision is the gateway's verdict.
type Decision string

const (
	DecisionAllow    Decision = "allow"
	DecisionBlock    Decision = "block"
	DecisionEscalate Decision = "escalate"
)

// Check identifies which stage produced the decision. Empty for an
// allow that passed every stage; one of the named values otherwise.
//
// CheckUpstream is set for events about the post-pipeline forward to
// the configured upstream tool server. An allow + CheckUpstream means
// "the gateway authorized the call AND successfully forwarded it"; a
// block + CheckUpstream means "the gateway authorized the call but
// could not deliver it" (timeout, transport error, upstream 5xx).
type Check string

const (
	CheckNone       Check = ""
	CheckCapability Check = "capability"
	CheckIntent     Check = "intent"
	// CheckProvenance is the optional fifth check (chronologically
	// third in pipeline order, between intent and policy) added for
	// AAI03 memory poisoning defense. Only emitted when the tenant
	// has provenance enabled. See internal/provenance and the design
	// doc at memos/aai03-memory-provenance-design.md.
	CheckProvenance Check = "provenance"
	// CheckActionGuard is the effect-level hold (Semantic Action Resolver +
	// mandatory hold + plan-level correlation). Runs before policy; blocks or
	// escalates irreversible high-value and create-then-pay actions.
	CheckActionGuard Check = "action_guard"
	// CheckRefVerify is the reference-verification (vendor-master) control.
	// Runs after the action guard and before the segmentation/policy stages:
	// verifies a payment's payee against the system-of-record vendor master and
	// quarantines (holds for approval) on mismatch, unknown payee, or an
	// unavailable reference source (fail-closed). See internal/refverify.
	CheckRefVerify Check = "reference_verification"
	// CheckDeception is the inline decoy engagement detector. Blocks (and
	// contains) a call that touched a decoy: an asset no legitimate agent,
	// task, or token ever has a reason to reach. See internal/deception.
	CheckDeception Check = "deception"
	// CheckEastWest is the agent-to-agent (east-west) zone authorization
	// (agent-as-tool model, default-deny). Blocks a call from one agent to
	// another when no zone edge or token allowlist permits it.
	CheckEastWest Check = "east_west"
	// CheckZoneScope is the per-zone north-south tool scope. Blocks a call to
	// a tool the caller's zone is not scoped to reach.
	CheckZoneScope Check = "zone_scope"
	CheckPolicy    Check = "policy"
	CheckBudget    Check = "budget"
	CheckUpstream  Check = "upstream"
	// CheckPII is the response-stream PII filter (LLM02). Unlike the
	// other checks which evaluate the request, CheckPII events
	// describe the gateway's decision on what the upstream tool
	// returned: allow (no PII matched), redact (matches replaced with
	// [REDACTED:<class>] markers and the body forwarded), or block
	// (response refused; agent receives -32015). The audit row
	// records counts per PII class — never the matched values.
	// Opt-in feature; only emitted when the tenant has the filter
	// enabled. See internal/pii and memos/llm02-pii-filter-design.md.
	CheckPII Check = "pii"
	// CheckOutputSchema is the response-schema validator (LLM05).
	// Like CheckPII, it describes the gateway's decision on what the
	// upstream returned: allow (response matched its declared schema),
	// strip (undeclared fields/wrong-type scalars removed and the body
	// forwarded), or block (response refused; agent receives -32016).
	// Per-violation-kind counts go into the audit row; matched values
	// never leave the gateway. Opt-in feature; only emitted when the
	// operator has declared a schema for the tool. See
	// internal/outputschema and memos/llm05-output-schema-design.md.
	CheckOutputSchema Check = "output_schema"
	// CheckTenantScope is the per-tenant vector-scope check (LLM08).
	// Runs on the request side, after the PII filter, for tools the
	// operator has declared tenant-scoped. The audit row records the
	// violation kind (missing|wildcard|mismatch) and the tool, never
	// the matched filter value. Opt-in feature; only emitted when
	// the operator has marked specific tools via
	// INTENTGATE_TENANT_SCOPED_TOOLS. See internal/tenantscope.
	CheckTenantScope Check = "tenant_scope"
	// CheckFaultIsolation is the per-tool bulkhead + circuit breaker
	// check (AGENT08). Only emitted when the layer is enabled AND a
	// call was refused fail-fast (circuit_open or bulkhead_full).
	// Healthy calls produce no audit row from this stage — the
	// downstream upstream check already records every forward.
	CheckFaultIsolation Check = "fault_isolation"
	// CheckToolSchema is the inbound tool-schema sanitizer (tool-poisoning
	// defense). Emitted when an inbound tool definition is sanitized (stripped),
	// held for drift review, or blocked as poisoned. See internal/toolschema.
	CheckToolSchema Check = "tool_schema"
	// CheckVelocity is the runtime velocity / monetary circuit breaker. Emitted
	// when a call is refused for exceeding a per-window rate or spend cap. See
	// internal/velocity.
	CheckVelocity Check = "velocity"
	// CheckSessionRewind is the self-healing session rewind. Emitted when a
	// blocked call triggers a rollback to the last verified-safe checkpoint and
	// a signed recovery envelope is issued. See internal/sessionrewind.
	CheckSessionRewind Check = "session_rewind"
)

// Event is the on-the-wire audit record.
//
// Fields are deliberately small and stable. Add new optional fields to
// the end; do not rename existing ones — downstream SIEM mappings will
// break.
type Event struct {
	// Timestamp is RFC3339 with nanosecond precision in UTC.
	Timestamp string `json:"ts"`
	// EventName is a stable string for routing in SIEMs.
	EventName string `json:"event"`
	// Schema version of this event shape.
	SchemaVersion string `json:"schema_version"`

	Decision Decision `json:"decision"`
	Check    Check    `json:"check,omitempty"`
	Reason   string   `json:"reason,omitempty"`

	// Summary is a one-line, human-readable description of the event,
	// PagerDuty-style ("BLOCK place_purchase_order by agent-procure
	// (policy: amount over 5000 EUR)"). It is stamped by the SIEM
	// routing layer (internal/siem) on events forwarded to an alerting
	// sink, so a Sentinel analytics rule or a PagerDuty-style channel
	// has a readable title without parsing the fields. It is left empty
	// on the raw audit record and the cold-storage (S3) stream, and it
	// is NOT part of the canonical, hash-chained event, so it never
	// affects tamper-evidence.
	Summary string `json:"summary,omitempty"`

	// Tenant is the trust-domain namespace this event was authorized
	// under. Read from the verified capability token; never from the
	// untrusted request. SOC analysts in multi-tenant deployments
	// filter on this field to scope a query.
	Tenant string `json:"tenant,omitempty"`

	// EventID is a gateway-generated id, stamped at emit time. The audit
	// store also assigns a sequence number, but that is allocated on insert
	// and the handler never sees it, so it cannot be used to correlate an
	// event with anything produced while handling the call.
	//
	// Its purpose is joining a decision to the response it produced: the
	// captured payload (internal/payloads) is keyed by this value.
	//
	// Deliberately NOT part of the canonical hash. See ResultSHA256 below for
	// why, and note the same caveat applies here.
	EventID string `json:"event_id,omitempty"`

	// ResultSHA256 is the hex SHA-256 of the response the upstream returned,
	// hashed BEFORE redaction. Present only when payload capture is on for
	// this tool. It is what lets an operator prove which response the agent
	// received without the body itself living in the audit stream.
	//
	// NOT part of the canonical hash, for the same reason arg_values is
	// excluded: the canonical form is an explicit struct mirror, and adding a
	// field to it would change the canonical bytes of every event already
	// written, breaking verification of existing chains. Making the response
	// hash tamper-evident requires a chain-version bump, which is a separate
	// and deliberate change.
	ResultSHA256 string `json:"result_sha256,omitempty"`
	// ResultBytes is the size of that raw response. Safe to hash-exclude and
	// safe to keep: a size is not customer data, and "this returned 40MB" is
	// often the whole finding.
	ResultBytes int `json:"result_bytes,omitempty"`
	// ResultStored says a redacted copy was retained and can be fetched.
	// False with a non-empty ResultSHA256 means the response was hashed but
	// the body was not kept, which is a legitimate posture on its own.
	ResultStored bool `json:"result_stored,omitempty"`

	// Actor (the AI agent making the call).
	AgentID   string `json:"agent_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`

	// Resource (the tool the agent was trying to invoke).
	Tool    string   `json:"tool"`
	ArgKeys []string `json:"arg_keys,omitempty"`
	// ArgValues is the redacted view of the call's argument values,
	// populated only when the gateway is configured with
	// INTENTGATE_AUDIT_PERSIST_ARG_VALUES=scalars (or =raw). Default
	// is to leave this empty so the audit log preserves its strict
	// keys-only privacy posture. When populated, the map mirrors
	// ArgKeys: every key in ArgValues appears in ArgKeys.
	// See audit.RedactionMode and audit.RedactArgs for the per-mode
	// rules — in particular: under "scalars" mode (the recommended
	// opt-in), numbers, booleans, and nulls survive; strings,
	// arrays-of-strings, and string-valued nested map entries are
	// replaced with null.
	ArgValues map[string]any `json:"arg_values,omitempty"`

	// Capability token identity (the jti). Helpful for correlating an
	// incident back to the issuance event.
	CapabilityTokenID string `json:"capability_token_id,omitempty"`
	// RootCapabilityTokenID is the JTI of the chain root for an
	// attenuated/delegated token. Equal to CapabilityTokenID for
	// root tokens. Lets a SOC analyst reconstruct a delegation tree
	// from the audit log: events with the same root_jti but different
	// caveat_count traversed different delegation paths.
	RootCapabilityTokenID string `json:"root_capability_token_id,omitempty"`
	// CaveatCount is the number of caveats currently bound to the
	// token's chain. Coarse-grained "is this more constrained than
	// that?" telemetry; not a security claim.
	CaveatCount int `json:"caveat_count,omitempty"`
	// PendingID correlates an "escalate" event with the eventual
	// "allow" or "block" event for the same human-approval flow.
	// SOC analyst: filter by pending_id to see the full lifecycle.
	PendingID string `json:"pending_id,omitempty"`
	// DecidedBy records the operator identity for the resolving
	// allow/block event after a human approval. Empty for direct
	// (non-escalated) decisions.
	DecidedBy string `json:"decided_by,omitempty"`
	// Intent summary captured by the extractor (one line of the user
	// prompt). Never the raw prompt — that may contain sensitive data.
	IntentSummary string `json:"intent_summary,omitempty"`

	// LatencyMS is wall-clock time the gateway spent on this request.
	LatencyMS int64 `json:"latency_ms"`

	// RemoteIP is the agent's source address as seen by the gateway.
	RemoteIP string `json:"remote_ip,omitempty"`

	// UpstreamStatus is the HTTP status code returned by the configured
	// upstream tool server, when a forward was attempted. Zero when the
	// gateway was in stub mode (no upstream configured) or when the
	// failure happened before any HTTP response (transport, timeout).
	UpstreamStatus int `json:"upstream_status,omitempty"`

	// RequiresStepUp marks the call as requiring a fresh out-of-band
	// step-up authentication factor (TOTP / WebAuthn / hardware key).
	// Populated from the Rego policy decision's `requires_step_up`
	// field. Advisory: the decision (allow/block/escalate) is still
	// authoritative for whether the call proceeded — this flag tells
	// downstream observers (the Pro console's high-risk feed, SIEM
	// dashboards) that the operation deserves extra scrutiny even
	// when it was allowed. A Rego policy enforcing strict step-up
	// returns both `allow: false` AND `requires_step_up: true`; a
	// policy observing only returns `allow: true` + `requires_step_up: true`.
	RequiresStepUp bool `json:"requires_step_up,omitempty"`

	// ElevationID is the JIT-elevation row id the calling operator
	// held when this event was emitted (Pro v2 #5, session 58).
	// Empty for events from non-elevated sessions and for agent
	// requests (which don't go through operator JIT). When non-empty,
	// it links the event back to the approval row in console-pro's
	// console_elevations table — an auditor can pull every event
	// performed during one elevation window with a single query, and
	// console-pro's compliance pack joins on this to show "who
	// approved the action that did X."
	//
	// Sourced from the `X-IntentGate-Elevation-Id` HTTP header on
	// admin endpoints (set by console-pro's gateway client when the
	// signed-in operator has an active elevation). The gateway
	// itself doesn't validate the id — it's metadata only; the
	// audit row's combination of (elevation_id, decided_by) is what
	// the auditor verifies against the elevation table.
	ElevationID string `json:"elevation_id,omitempty"`
}

// NewEvent constructs an Event with the timestamp, event name, and
// schema version pre-populated. Callers fill in the rest.
//
// Schema versions:
//
//	"1" — gateway 0.1–0.6: original OCSF-lite shape.
//	"2" — gateway 0.7+: adds root_capability_token_id and caveat_count
//	      for delegation visibility. Field-add is backwards compatible
//	      for SIEM mappings — old fields unchanged, new fields
//	      omitempty when zero.
//	"3" — gateway 0.9+: adds `tenant` for multi-tenant deployments.
//	      Backwards-compatible field-add; single-tenant deployments
//	      always emit `tenant=default`.
//	"4" — gateway 1.3+: adds optional `arg_values` carrying a redacted
//	      view of the tool call's arguments. Omitempty when the operator
//	      hasn't opted in via INTENTGATE_AUDIT_PERSIST_ARG_VALUES, so
//	      v3 SIEM mappings keep working unchanged. The schema_version
//	      bump signals to dry-run consumers that ArgValues may be
//	      populated; older events still read NULL and dry-run falls
//	      back to keys-only replay.
//	"5" — gateway 1.6+: adds optional `requires_step_up` boolean
//	      sourced from the Rego policy decision. Omitempty when the
//	      policy didn't flag the call, so v4 SIEM mappings keep
//	      working unchanged. The Pro console reads this field to
//	      surface a high-risk-feed badge; SIEMs can route on it for
//	      alert pipelines.
//	"6" — gateway 1.8+: adds optional `elevation_id` linking the
//	      event back to a JIT admin elevation (Pro v2 #5). Empty
//	      when no operator JIT was active. The Pro console joins on
//	      this to surface "every operation performed under
//	      elevation X" queries. v5 SIEM mappings keep working —
//	      omitempty means absent rows don't change the wire shape.
func NewEvent(d Decision, tool string) Event {
	return Event{
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		EventName:     "intentgate.tool_call",
		SchemaVersion: "6",
		Decision:      d,
		Tool:          tool,
	}
}

// Emitter is the contract for audit-event sinks.
//
// Emit is called synchronously from the request path. Implementations
// MUST NOT block: log emission is a side effect of authorization, not
// part of it. If the sink is slow (network, disk), buffer and drop —
// preferable to stalling tool-call evaluation.
type Emitter interface {
	Emit(ctx context.Context, e Event)
}

// StdoutEmitter writes one JSON event per line to a configured writer
// (stdout by default). Safe for concurrent use.
type StdoutEmitter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewStdoutEmitter returns an emitter writing to os.Stdout. Use
// [NewWriterEmitter] if you need to direct events somewhere else.
func NewStdoutEmitter() *StdoutEmitter {
	return &StdoutEmitter{w: os.Stdout}
}

// NewWriterEmitter wraps an arbitrary io.Writer. Useful in tests and
// for wiring a buffered or rotating writer in production.
func NewWriterEmitter(w io.Writer) *StdoutEmitter {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutEmitter{w: w}
}

// Emit serializes the event and writes it as one line. Errors are
// silently dropped — there is nothing useful to do if audit fails
// inline, and we don't want audit to backpressure tool-call traffic.
//
// Operators worried about silent loss should pipe stdout through a
// reliable shipper (vector, fluent-bit, promtail) which has its own
// retry semantics.
func (s *StdoutEmitter) Emit(_ context.Context, e Event) {
	if s == nil {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(line)
	_, _ = s.w.Write([]byte{'\n'})
}

// NullEmitter drops every event. Use for tests, benchmarks, and
// deployments where audit is intentionally disabled.
type NullEmitter struct{}

// NewNullEmitter returns the no-op emitter.
func NewNullEmitter() NullEmitter { return NullEmitter{} }

// Emit on NullEmitter is a no-op.
func (NullEmitter) Emit(context.Context, Event) {}

// FanOutEmitter calls Emit on each underlying emitter in order. Used
// to send the same event to multiple sinks (e.g. stdout AND a
// Postgres-backed store) without entangling either implementation
// with the other's failure modes.
//
// The fan-out is synchronous and best-effort: each underlying Emit is
// called in turn, no error is bubbled up (the [Emitter] contract is
// fire-and-forget). Underlying emitters that need async semantics
// must implement them internally — see auditstore.NewEmitter for the
// canonical async-with-drop pattern.
//
// A nil or empty FanOutEmitter is a no-op.
type FanOutEmitter struct {
	emitters []Emitter
}

// NewFanOut returns an emitter that forwards to each non-nil emitter
// in the argument list. Order is preserved.
func NewFanOut(emitters ...Emitter) *FanOutEmitter {
	out := make([]Emitter, 0, len(emitters))
	for _, e := range emitters {
		if e != nil {
			out = append(out, e)
		}
	}
	return &FanOutEmitter{emitters: out}
}

// Emit dispatches to every underlying emitter.
func (f *FanOutEmitter) Emit(ctx context.Context, e Event) {
	if f == nil {
		return
	}
	for _, em := range f.emitters {
		em.Emit(ctx, e)
	}
}

// FromTarget constructs an emitter from an INTENTGATE_AUDIT_TARGET
// string. Recognized targets:
//
//   - "stdout" or empty — [StdoutEmitter] writing to os.Stdout
//   - "none" or "off"   — [NullEmitter]
//
// Unknown targets return an error so misconfiguration fails at
// startup rather than at audit time.
func FromTarget(target string) (Emitter, string, error) {
	switch target {
	case "", "stdout":
		return NewStdoutEmitter(), "stdout", nil
	case "none", "off":
		return NewNullEmitter(), "none", nil
	default:
		return nil, "", fmt.Errorf("unknown audit target %q (want stdout|none)", target)
	}
}
