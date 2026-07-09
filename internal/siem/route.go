package siem

import (
	"context"
	"fmt"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// EventMode selects which audit events a SIEM sink receives.
//
// The two-tier logging pattern is: send the full raw stream to cheap
// cold storage (the S3 sink) and send only findings to the expensive
// hot tier (Microsoft Sentinel, Splunk, or a PagerDuty-style channel,
// reached directly or through a shipper such as Logstash). EventMode is
// what makes a single sink carry either the whole stream or just the
// findings, so an operator can tier by destination without a second
// pipeline.
type EventMode string

const (
	// ModeAll forwards every audit event, the raw stream. Use it for
	// cold storage such as S3.
	ModeAll EventMode = "all"
	// ModeFindings forwards only findings: blocks, escalations, and
	// allow-but-flagged (step-up) events. Use it for an alerting SIEM
	// so the hot tier holds only what a SOC needs to see, which is the
	// whole point of keeping Sentinel cheap while raw logs age in S3.
	ModeFindings EventMode = "findings"
)

// ParseEventMode maps an operator-supplied value onto an EventMode.
// Unknown or empty input returns def, so the caller can apply a smart
// default (for example, findings when an S3 cold tier is configured,
// all otherwise).
func ParseEventMode(raw string, def EventMode) EventMode {
	switch EventMode(strings.ToLower(strings.TrimSpace(raw))) {
	case ModeAll:
		return ModeAll
	case ModeFindings:
		return ModeFindings
	default:
		return def
	}
}

// IsFinding reports whether an audit event is a finding worth routing
// to an alerting SIEM. Findings are the non-routine decisions: a block,
// an escalation (held for a human), or an allow that the policy flagged
// for step-up. A routine allow is not a finding.
func IsFinding(e audit.Event) bool {
	switch e.Decision {
	case audit.DecisionBlock, audit.DecisionEscalate:
		return true
	case audit.DecisionAllow:
		return e.RequiresStepUp
	default:
		return false
	}
}

// BuildSummary renders a one-line, human-readable description of an
// event, PagerDuty-style, so an alert receiver has a readable title
// without parsing the JSON. Example:
//
//	BLOCK place_purchase_order by agent-procure (policy: amount over 5000 EUR)
func BuildSummary(e audit.Event) string {
	agent := e.AgentID
	if agent == "" {
		agent = "unknown-agent"
	}
	tool := e.Tool
	if tool == "" {
		tool = "unknown-tool"
	}
	summary := fmt.Sprintf("%s %s by %s", strings.ToUpper(string(e.Decision)), tool, agent)
	switch {
	case e.Check != "" && e.Reason != "":
		summary += fmt.Sprintf(" (%s: %s)", e.Check, e.Reason)
	case e.Check != "":
		summary += fmt.Sprintf(" (%s)", e.Check)
	case e.Reason != "":
		summary += fmt.Sprintf(" (%s)", e.Reason)
	}
	if e.RequiresStepUp && e.Decision == audit.DecisionAllow {
		summary += " [step-up flagged]"
	}
	return summary
}

// routingEmitter wraps a SIEM sink and does two things: it optionally
// forwards only findings (ModeFindings), and it stamps a human-readable
// Summary on every event it forwards. It forwards Stop to the wrapped
// sink so graceful shutdown still drains the underlying batch worker.
//
// Emit takes the event by value, so the Summary it stamps is local to
// this sink's copy. A raw sink (S3) that is not wrapped still receives
// the untouched event, which keeps the cold tier a faithful raw record.
type routingEmitter struct {
	inner        audit.Emitter
	findingsOnly bool
}

// NewRoutingEmitter wraps inner. When mode is ModeFindings it forwards
// only findings; in every mode it enriches forwarded events with a
// PagerDuty-style Summary.
func NewRoutingEmitter(inner audit.Emitter, mode EventMode) audit.Emitter {
	return &routingEmitter{inner: inner, findingsOnly: mode == ModeFindings}
}

// Emit applies the findings filter, then stamps the summary, then
// forwards to the wrapped sink.
func (r *routingEmitter) Emit(ctx context.Context, e audit.Event) {
	if r.findingsOnly && !IsFinding(e) {
		return
	}
	if e.Summary == "" {
		e.Summary = BuildSummary(e)
	}
	r.inner.Emit(ctx, e)
}

// Stop forwards graceful shutdown to the wrapped sink so its batch
// worker drains before the process exits.
func (r *routingEmitter) Stop(ctx context.Context) error {
	if s, ok := r.inner.(Stoppable); ok {
		return s.Stop(ctx)
	}
	return nil
}
