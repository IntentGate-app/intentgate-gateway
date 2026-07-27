// Package bundleadapter wires the bundle evaluator's interface seams
// (bundle.MagnitudeGuard, bundle.VendorVerifier, bundle.AuditSink) to the real
// gateway engines (actionir/actionguard, refverify, audit). Keeping the adapters
// here lets internal/bundle stay dependency-free and unit-testable, while these
// thin structs bind it to production behaviour.
package bundleadapter

import (
	"context"
	"fmt"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/bundle"
	"github.com/IntentGate-app/intentgate-gateway/internal/refverify"
)

/* --------------------------- ActionGuard adapter ------------------------- */

// ActionGuardAdapter implements bundle.MagnitudeGuard. It applies the PER-BUNDLE
// magnitude threshold (which the gateway-wide actionguard.Config cannot express
// per subject): an irreversible action whose financial magnitude exceeds the
// bundle's max_cents escalates for human approval. The financial magnitude is
// resolved from the call arguments with actionir (ir.MagnitudeCents) upstream;
// use ResolveMagnitude to populate EvaluationRequest.PayloadCents.
//
// This does not replace the gateway-wide actionguard.Guard (unbounded-delete
// block, plan-level fraud escalation, threat-intel feed): that keeps running on
// the main request path. This adapter adds the grant-specific money ceiling.
type ActionGuardAdapter struct{}

func (ActionGuardAdapter) Escalate(tool string, payloadCents, maxCents int64, irreversible []string) (bool, string) {
	if maxCents <= 0 || payloadCents <= 0 {
		return false, ""
	}
	if !containsStr(irreversible, tool) {
		return false, ""
	}
	if payloadCents > maxCents {
		return true, fmt.Sprintf(
			"payload magnitude %d cents exceeds bundle threshold %d cents; holding for human approval",
			payloadCents, maxCents,
		)
	}
	return false, ""
}

// ResolveMagnitude resolves a call's financial magnitude (cents) via actionir,
// so the MCP handler can set EvaluationRequest.PayloadCents before Evaluate().
func ResolveMagnitude(tool string, args map[string]any) int64 {
	return actionir.Resolve(tool, args).MagnitudeCents
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

/* ---------------------------- RefVerify adapter -------------------------- */

// RefVerifyAdapter implements bundle.VendorVerifier by looking the counterparty
// up in the reference vendor master. Unknown payee -> not approved (quarantine);
// a lookup error or an absent master -> fail closed (hold) when FailClosed.
type RefVerifyAdapter struct {
	Master     refverify.VendorMaster
	FailClosed bool
}

func (a RefVerifyAdapter) VendorApproved(_ context.Context, counterparty string) (bool, string) {
	if a.Master == nil {
		if a.FailClosed {
			return false, "vendor master unavailable; holding (fail-closed)"
		}
		return true, ""
	}
	if counterparty == "" {
		if a.FailClosed {
			return false, "no counterparty on the call; holding (fail-closed)"
		}
		return true, ""
	}
	if _, ok, err := a.Master.Lookup(counterparty); err != nil {
		return false, "vendor master lookup error; holding (fail-closed)"
	} else if !ok {
		return false, fmt.Sprintf("payee %q is not on the approved vendor master; quarantine", counterparty)
	}
	return true, ""
}

/* ----------------------------- Audit adapter ----------------------------- */

// AuditSinkAdapter implements bundle.AuditSink by turning each dual-path decision
// into an audit.Event and emitting it. Pass an emitter that fans out to the
// console real-time stream (audit.StreamHub), stdout/SIEM, and any proof sink, so
// operators see live PERMIT/DENY/ESCALATE with reason codes and the evidence is
// retained in-VPC.
type AuditSinkAdapter struct {
	Emitter audit.Emitter
}

func (a AuditSinkAdapter) Emit(ctx context.Context, rec bundle.ProofRecord) {
	if a.Emitter == nil {
		return
	}
	e := audit.NewEvent(mapDecision(rec.Decision), rec.Tool)
	e.EventName = "intentgrant.proof"
	e.AgentID = rec.Subject
	e.Reason = rec.Reason
	// First-class, hashed Layer-4 proof linkage (audit schema v7): the exact
	// policy version (bundle_id) and its content digest are bound into the
	// tamper-evident chain and queryable as top-level SIEM keys.
	e.BundleID = rec.BundleID
	e.BundleDigest = rec.BundleDigest
	e.Summary = fmt.Sprintf("%s %s [%s]", rec.Decision, rec.Tool, rec.Check)
	a.Emitter.Emit(ctx, e)
}

func mapDecision(d bundle.Decision) audit.Decision {
	switch d {
	case bundle.DecisionPermit:
		return audit.DecisionAllow
	case bundle.DecisionEscalate:
		return audit.DecisionEscalate
	default: // DENY, RESTRICT
		return audit.DecisionBlock
	}
}

/* ------------------------------- wiring ---------------------------------- */

// NewEvaluator builds a DualPathEvaluator wired to all three real engines. The
// MCP handler calls this once at startup and Evaluate() per tool call.
func NewEvaluator(reg *bundle.BundleRegistry, master refverify.VendorMaster, failClosed bool, emitter audit.Emitter) *bundle.DualPathEvaluator {
	return bundle.NewDualPathEvaluator(
		reg,
		ActionGuardAdapter{},
		RefVerifyAdapter{Master: master, FailClosed: failClosed},
		AuditSinkAdapter{Emitter: emitter},
	)
}
