package bundle

import (
	"context"
	"fmt"
	"time"
)

// Decision is one of the four crisp runtime outcomes.
type Decision string

const (
	DecisionPermit   Decision = "PERMIT"
	DecisionDeny     Decision = "DENY"
	DecisionEscalate Decision = "ESCALATE" // human-in-the-loop hold (step-up)
	DecisionRestrict Decision = "RESTRICT" // restrict / redact (maps to policy PIIFilter)
)

// EvaluationRequest is one tool call to authorize.
type EvaluationRequest struct {
	Subject      string            // SPIFFE id / agent id; keys the active bundle
	Tool         string            // resolved tool name
	PayloadCents int64             // ir.MagnitudeCents resolved upstream (0 if n/a)
	Counterparty string            // for the vendor-master check
	SessionID    string            // for actionguard session correlation
	Context      map[string]string // free-form, carried into the proof record
	Now          time.Time         // injectable clock; zero => time.Now()
}

// EvaluationResult is the decision plus everything Proof (Layer 4) needs.
type EvaluationResult struct {
	Decision     Decision      `json:"decision"`
	Check        string        `json:"check"` // which stage decided
	Reason       string        `json:"reason"`
	BundleID     string        `json:"bundle_id"`
	BundleDigest string        `json:"bundle_digest"`
	Monitor      bool          `json:"monitor"` // true if observe-only downgraded a block/hold
	Latency      time.Duration `json:"latency"`
}

// MagnitudeGuard inspects a call's monetary magnitude. Implement with an adapter
// over the gateway's actionguard package: ir.MagnitudeCents vs EscalateOverCents,
// on irreversible actions only. Honest semantics: this ESCALATES (holds for a
// human), it does not hard-block.
type MagnitudeGuard interface {
	Escalate(tool string, payloadCents, maxCents int64, irreversible []string) (hold bool, reason string)
}

// VendorVerifier runs the reference-verification (vendor master) check. Implement
// with an adapter over the gateway's refverify package.
type VendorVerifier interface {
	VendorApproved(ctx context.Context, counterparty string) (approved bool, reason string)
}

// AuditSink receives one record per decision (Layer 4 Proof). Implement with an
// adapter over the gateway's audit / proofofintent packages, which handle in-VPC
// retention and pushing to the console's real-time dual-identity stream.
type AuditSink interface {
	Emit(ctx context.Context, rec ProofRecord)
}

// ProofRecord is the structured evidence emitted for one decision.
type ProofRecord struct {
	Subject      string            `json:"subject"`
	Tool         string            `json:"tool"`
	Decision     Decision          `json:"decision"`
	Check        string            `json:"check"`
	Reason       string            `json:"reason"`
	BundleID     string            `json:"bundle_id"`
	BundleDigest string            `json:"bundle_digest"`
	Context      map[string]string `json:"context,omitempty"`
	At           time.Time         `json:"at"`
}

// DualPathEvaluator evaluates a request against the active bundle: Path A (static
// caveats, local) then Path B (ActionGuard / reference verification). The guards
// and audit sink are optional seams; nil ones are skipped so the package builds
// and tests without a hard dependency on actionguard/refverify/audit.
type DualPathEvaluator struct {
	reg    *BundleRegistry
	mag    MagnitudeGuard
	vendor VendorVerifier
	audit  AuditSink
}

func NewDualPathEvaluator(reg *BundleRegistry, mag MagnitudeGuard, vendor VendorVerifier, audit AuditSink) *DualPathEvaluator {
	return &DualPathEvaluator{reg: reg, mag: mag, vendor: vendor, audit: audit}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Evaluate runs the dual path and returns a decision. Path A is local and adds
// sub-millisecond deterministic overhead; Path B runs only where a rule needs
// the payload, and can hold/escalate.
func (e *DualPathEvaluator) Evaluate(ctx context.Context, req EvaluationRequest) EvaluationResult {
	start := time.Now()
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

	b := e.reg.GetActive(req.Subject)
	if b == nil {
		return e.finish(ctx, req, EvaluationResult{
			Decision: DecisionDeny, Check: "system", Reason: "no active policy bundle for subject",
		}, nil, start, now)
	}
	digest, _ := Digest(b)

	// -- Path A: static caveats (local, fast) --------------------------------
	cav := b.StaticCapabilities.Caveats
	if !cav.ValidUntil.IsZero() && now.After(cav.ValidUntil) {
		return e.decide(ctx, req, b, EvaluationResult{
			Decision: DecisionDeny, Check: "capability", Reason: "grant validity window expired",
			BundleID: b.BundleID, BundleDigest: digest,
		}, start, now)
	}
	if len(cav.AllowedTools) > 0 && !contains(cav.AllowedTools, req.Tool) {
		return e.decide(ctx, req, b, EvaluationResult{
			Decision: DecisionDeny, Check: "capability",
			Reason:   fmt.Sprintf("tool %q not permitted by static grant", req.Tool),
			BundleID: b.BundleID, BundleDigest: digest,
		}, start, now)
	}

	// -- Path B: ActionGuard payload inspection ------------------------------
	if ag := b.RuntimeGuardRules.ActionGuard; ag != nil && ag.InspectPayload && ag.MagnitudeCheck.Enabled && e.mag != nil {
		if hold, reason := e.mag.Escalate(req.Tool, req.PayloadCents, ag.MagnitudeCheck.MaxCents, ag.IrreversibleActions); hold {
			return e.decide(ctx, req, b, EvaluationResult{
				Decision: DecisionEscalate, Check: "actionguard_magnitude", Reason: reason,
				BundleID: b.BundleID, BundleDigest: digest,
			}, start, now)
		}
	}
	if rv := b.RuntimeGuardRules.ReferenceVerification; rv != nil && rv.VendorMaster.Enabled && e.vendor != nil && req.Counterparty != "" {
		if approved, reason := e.vendor.VendorApproved(ctx, req.Counterparty); !approved {
			return e.decide(ctx, req, b, EvaluationResult{
				Decision: DecisionEscalate, Check: "refverify_vendor_master", Reason: reason,
				BundleID: b.BundleID, BundleDigest: digest,
			}, start, now)
		}
	}

	return e.decide(ctx, req, b, EvaluationResult{
		Decision: DecisionPermit, Check: "policy", Reason: "allowed by intentgrant bundle",
		BundleID: b.BundleID, BundleDigest: digest,
	}, start, now)
}

// decide applies the observe-only (monitor) downgrade, then finishes. In monitor
// mode a would-be block/hold is logged but not enforced: the decision is
// downgraded to PERMIT with the intended outcome preserved in the reason.
func (e *DualPathEvaluator) decide(ctx context.Context, req EvaluationRequest, b *CompiledGateBundle, res EvaluationResult, start, now time.Time) EvaluationResult {
	if b.StaticCapabilities.Caveats.ObserveOnly && res.Decision != DecisionPermit {
		res.Reason = "monitor: would " + string(res.Decision) + " (" + res.Reason + ")"
		res.Decision = DecisionPermit
		res.Monitor = true
	}
	return e.finish(ctx, req, res, b, start, now)
}

// finish stamps latency and emits the proof record (Layer 4) when configured.
func (e *DualPathEvaluator) finish(ctx context.Context, req EvaluationRequest, res EvaluationResult, b *CompiledGateBundle, start, now time.Time) EvaluationResult {
	res.Latency = time.Since(start)
	if e.audit != nil && (b == nil || b.AttestationConfig.EmitProof) {
		e.audit.Emit(ctx, ProofRecord{
			Subject: req.Subject, Tool: req.Tool, Decision: res.Decision, Check: res.Check,
			Reason: res.Reason, BundleID: res.BundleID, BundleDigest: res.BundleDigest,
			Context: req.Context, At: now,
		})
	}
	return res
}
