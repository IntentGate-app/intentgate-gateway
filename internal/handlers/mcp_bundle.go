package handlers

import (
	"context"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
	"github.com/IntentGate-app/intentgate-gateway/internal/bundle"
)

// bundleDecision runs the IntentGrant compiled-authority evaluator for one tool
// call. It is strictly additive: it returns governed=false (and the caller does
// nothing) unless both the registry and evaluator are configured AND a signed
// bundle has actually been propagated for this subject. So a gateway with no
// grants published behaves exactly as before.
//
// When a bundle governs the subject, it runs Path A (static caveats: tool
// allow-list, expiry, observe-only) and Path B (per-bundle magnitude via
// ActionGuard semantics, vendor master via RefVerify), emits a Layer-4
// ProofRecord through the configured AuditSink, and returns the decision for the
// caller to map onto the existing allow / hold / deny flow.
func (h *mcpHandler) bundleDecision(ctx context.Context, subject, tool string, args map[string]any, sessionID string) (bundle.EvaluationResult, bool) {
	if h.cfg.BundleEval == nil || h.cfg.BundleReg == nil {
		return bundle.EvaluationResult{}, false
	}
	if h.cfg.BundleReg.GetActive(subject) == nil {
		return bundle.EvaluationResult{}, false
	}
	req := bundle.EvaluationRequest{
		Subject:      subject,
		Tool:         tool,
		PayloadCents: actionir.Resolve(tool, args).MagnitudeCents,
		Counterparty: extractCounterparty(args),
		SessionID:    sessionID,
	}
	return h.cfg.BundleEval.Evaluate(ctx, req), true
}

// extractCounterparty pulls the payee/vendor from common argument keys so the
// reference-verification path can check it. Empty when the call has no obvious
// counterparty (the vendor check then no-ops for that call).
func extractCounterparty(args map[string]any) string {
	for _, k := range []string{"payee", "recipient", "vendor", "counterparty", "destination", "beneficiary", "to"} {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
