package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// A deterministic safety check for a policy change, run before it goes
// live.
//
// # What this is, and what it is not
//
// It is a smoke detector. It reads two things the gateway already has —
// the dry-run of the candidate against real historical traffic, and the
// text of the current and candidate policies — and reports the loud,
// mechanical, high-blast-radius mistakes: a change that blocks most of
// the estate, one that quietly opens traffic that was being denied, one
// that errors on real inputs, one that no longer denies anything.
//
// It is NOT a judge of intent. It can say "this denies every transfer
// tested in the last day"; it cannot say whether you meant to. Freezing
// transfers during a fraud incident and freezing them by accident
// produce the identical report. The magnitude is the machine's to
// measure; the meaning is the operator's to decide, and every caller of
// this package has to present it that way or it becomes the false-
// confidence trap it was built to avoid.
//
// It does NOT auto-correct. Where a fix is unambiguous it says so in
// words (Finding.Suggestion), but rewriting the control that governs
// every agent call is a decision a person owns.
//
// # Why deterministic rather than a model
//
// Same change, same report, every time. An auditor asking "why did this
// pass" gets one answer, not a model's mood, and nothing leaves the box.
// The trade is that it only catches patterns we have named — it will
// miss a subtle logic error that does not move the numbers. That gap is
// real and is where a model-based second opinion would earn its place;
// it is not this package's job to pretend otherwise.
//
// # The load-bearing honesty: Tested
//
// Report.Tested is false when the dry-run had no traffic to evaluate
// against. A change checked against zero events is not "safe"; it is
// unchecked, and those are opposite conditions that look identical if
// the panel just shows a green tick. Callers MUST distinguish them.

// Severity orders the findings. Critical is a change that is dangerous
// on its face; warning is a large effect that is probably deliberate but
// worth a second look; info is context, not alarm.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// Finding is one thing the check noticed.
type Finding struct {
	Severity Severity `json:"severity"`
	// Code is a stable machine key (e.g. "mass_block") so the console
	// can style or filter without parsing prose.
	Code   string `json:"code"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	// Suggestion is the corrective action, present ONLY where it is
	// unambiguous — "add back the default-deny you removed", not "you
	// probably meant something else". Empty when the fix depends on
	// intent the check cannot know.
	Suggestion string `json:"suggestion,omitempty"`
}

// Report is the whole verdict.
type Report struct {
	Findings []Finding `json:"findings"`
	// Blocking is true when any finding is critical. It is a
	// recommendation, not an enforcement: the handler decides whether a
	// critical finding stops a promote or merely warns. Naming it here
	// keeps that decision in one place.
	Blocking bool `json:"blocking"`
	// Tested is false when EventsEvaluated was zero — no traffic to
	// check against. The single most important field: without it the
	// caller cannot tell "found nothing wrong" from "looked at nothing".
	Tested bool `json:"tested"`
	// EventsEvaluated is echoed so the console can say what the verdict
	// is based on ("checked against 14,284 calls") rather than asking
	// the reader to trust a bare result.
	EventsEvaluated int `json:"events_evaluated"`
}

// Thresholds tune where a large effect becomes a finding. Defaults suit
// a general estate; a caller can widen them for a noisy pilot or tighten
// them for a bank. Zero value is NOT usable — call DefaultThresholds.
type Thresholds struct {
	// Share of evaluated traffic flipping allow→block that raises a
	// warning, and the higher share that makes it critical.
	MassBlockWarn float64
	MassBlockCrit float64
	// Share flipping block→allow that raises a warning. Deliberately
	// lower than the block thresholds: opening a hole the policy was
	// closing is more dangerous than closing one it was leaving open,
	// so it trips sooner.
	MassAllowWarn float64
	MassAllowCrit float64
	// Share newly routed to escalation/approval. A surge here does not
	// deny anything, but it floods the approval queue and can wedge
	// operations, so it is worth a warning.
	EscalateWarn float64
}

// DefaultThresholds returns the tuned starting point. The numbers are
// editorial judgement, not derived from any customer's traffic, and are
// documented as such so nobody reads them as a recommendation.
func DefaultThresholds() Thresholds {
	return Thresholds{
		MassBlockWarn: 0.10, // a tenth of traffic newly denied is worth a look
		MassBlockCrit: 0.40, // nearly half is almost never intended in one step
		MassAllowWarn: 0.05, // opening up trips at half the block threshold
		MassAllowCrit: 0.25,
		EscalateWarn:  0.20,
	}
}

// pctOf returns n/total as a fraction, guarding total==0.
func pctOf(n, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(n) / float64(total)
}

func humanPct(f float64) string {
	return fmt.Sprintf("%.0f%%", f*100)
}

// Analyze produces the report. It never returns an error: a policy that
// would not compile never reaches here (the dry-run rejects it first),
// and every check degrades to "say less" rather than failing.
//
// currentRego may be empty — the estate may have no promoted policy yet,
// in which case the removed-protection check simply has nothing to
// compare against and stays quiet, which is correct.
func Analyze(currentRego, candidateRego string, s DryRunSummary, th Thresholds) Report {
	r := Report{
		Tested:          s.EventsEvaluated > 0,
		EventsEvaluated: s.EventsEvaluated,
	}

	// No traffic to judge against. Say so plainly and stop: emitting
	// "no problems found" here would be the exact blank-vs-unchecked lie
	// this package exists to prevent.
	if s.EventsEvaluated == 0 {
		r.Findings = append(r.Findings, Finding{
			Severity: SeverityInfo,
			Code:     "not_tested",
			Title:    "Not checked against real traffic",
			Detail: "There were no recorded calls in the dry-run window to " +
				"evaluate this policy against, so this is not a clean bill of " +
				"health — it is an absence of evidence. Widen the window or " +
				"generate traffic before relying on it.",
		})
		// Still run the static checks below: they do not need traffic.
	}

	// --- traffic-based checks (need EventsEvaluated > 0) ---
	if s.EventsEvaluated > 0 {
		// Mass block: allow→block as a share of all evaluated calls.
		if blockPct := pctOf(s.AllowToBlock, s.EventsEvaluated); blockPct >= th.MassBlockWarn {
			sev := SeverityWarning
			if blockPct >= th.MassBlockCrit {
				sev = SeverityCritical
			}
			r.Findings = append(r.Findings, Finding{
				Severity: sev,
				Code:     "mass_block",
				Title:    "Blocks a large share of current traffic",
				Detail: fmt.Sprintf(
					"%d of %d recently-allowed calls (%s) would be denied by this "+
						"policy. If that is deliberate — a freeze, a tightening — proceed. "+
						"If not, this is the shape of an accidental over-block.",
					s.AllowToBlock, s.EventsEvaluated, humanPct(blockPct)),
			})
		}

		// Mass allow: block→allow. Trips sooner because opening a hole is
		// worse than closing one.
		if allowPct := pctOf(s.BlockToAllow, s.EventsEvaluated); allowPct >= th.MassAllowWarn {
			sev := SeverityWarning
			if allowPct >= th.MassAllowCrit {
				sev = SeverityCritical
			}
			r.Findings = append(r.Findings, Finding{
				Severity: sev,
				Code:     "mass_allow",
				Title:    "Opens traffic that is currently blocked",
				Detail: fmt.Sprintf(
					"%d of %d calls (%s) that are denied today would be allowed by "+
						"this policy. A policy that stops enforcing is quieter than one "+
						"that over-blocks and easy to ship by accident — confirm each of "+
						"these is meant to be permitted.",
					s.BlockToAllow, s.EventsEvaluated, humanPct(allowPct)),
			})
		}

		// Errors on real inputs. Any is notable: the policy threw on
		// traffic that actually occurred, so it will throw in production.
		if s.PolicyError > 0 {
			r.Findings = append(r.Findings, Finding{
				Severity: SeverityCritical,
				Code:     "policy_error",
				Title:    "Errors on real traffic",
				Detail: fmt.Sprintf(
					"This policy failed to evaluate %d of %d replayed calls. Whatever "+
						"the gateway does with an errored decision, it is not the "+
						"decision you wrote — fix the rule that throws before promoting.",
					s.PolicyError, s.EventsEvaluated),
				Suggestion: "Check the dry-run samples for the failing calls; the error " +
					"is usually a missing field or a type mismatch in one rule.",
			})
		}

		// Allows everything it saw. Distinct from mass-allow: this fires
		// when the candidate denied and escalated NOTHING across real
		// traffic, which is the fingerprint of a policy that fails open
		// or was gutted. Data-backed, so it can speak plainly where the
		// static fails-closed guess below only hedges.
		if s.CandidateBlock == 0 && s.CandidateEscalate == 0 && s.PolicyError == 0 {
			r.Findings = append(r.Findings, Finding{
				Severity: SeverityCritical,
				Code:     "allows_everything",
				Title:    "Denied nothing across the whole sample",
				Detail: fmt.Sprintf(
					"This policy allowed every one of the %d calls it was tested on and "+
						"denied none. Unless this estate is meant to permit all agent "+
						"traffic, the policy is not enforcing — check that it fails closed.",
					s.EventsEvaluated),
				Suggestion: "A policy should end with a default-deny so anything no rule " +
					"matched is denied rather than allowed.",
			})
		}

		// Escalation surge: floods the approval queue without denying.
		if escPct := pctOf(s.AllowToEscalate, s.EventsEvaluated); escPct >= th.EscalateWarn {
			r.Findings = append(r.Findings, Finding{
				Severity: SeverityWarning,
				Code:     "escalation_surge",
				Title:    "Sends a large share of traffic to approval",
				Detail: fmt.Sprintf(
					"%d of %d calls (%s) would newly require human approval. Nothing is "+
						"denied, but an approval queue this size can wedge operations — "+
						"make sure someone is staffed to clear it.",
					s.AllowToEscalate, s.EventsEvaluated, humanPct(escPct)),
			})
		}

		// No effect at all. Not dangerous, but usually means the wrong
		// draft was selected or an edit did nothing.
		if s.AllowToBlock == 0 && s.BlockToAllow == 0 &&
			s.AllowToEscalate == 0 && s.BlockToEscalate == 0 &&
			s.EscalateToAllow == 0 && s.EscalateToBlock == 0 && s.PolicyError == 0 {
			r.Findings = append(r.Findings, Finding{
				Severity: SeverityInfo,
				Code:     "no_change",
				Title:    "Changes no decisions",
				Detail: "This policy decides every replayed call exactly as the current " +
					"one does. That is fine if you are re-affirming the current policy; " +
					"if you expected a change, you may have selected the wrong draft.",
			})
		}
	}

	// --- static checks (no traffic needed) ---

	// Removed default-deny. A heuristic, and labelled as one: if the
	// current policy visibly fails closed and the candidate does not
	// appear to, warn — but never escalate a text-matching guess to
	// critical, because the candidate may fail closed in a form this
	// does not recognise.
	if currentRego != "" &&
		looksLikeFailsClosed(currentRego) && !looksLikeFailsClosed(candidateRego) {
		r.Findings = append(r.Findings, Finding{
			Severity: SeverityWarning,
			Code:     "maybe_removed_default_deny",
			Title:    "May have removed the default-deny",
			Detail: "The current policy ends by denying anything no rule matched; the " +
				"candidate does not obviously do the same. This is a text check, not a " +
				"proof, so confirm the candidate still fails closed.",
			Suggestion: "Keep a `default decision := {\"allow\": false, ...}` (or " +
				"`default allow := false`) as the last word so unmatched calls are denied.",
		})
	}

	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			r.Blocking = true
			break
		}
	}
	return r
}

// failsClosedPattern matches the two idiomatic ways an IntentGate policy
// denies by default: a `default decision` object whose allow is false,
// or a `default allow := false`. Whitespace-tolerant. This is a
// heuristic on purpose — a full answer needs the Rego compiler's view of
// the module, and a wrong "critical" here would train operators to
// ignore the checker, so the caller only ever treats a miss as a
// warning.
var failsClosedPattern = regexp.MustCompile(
	`(?is)default\s+decision\s*:?=?\s*\{[^}]*"allow"\s*:\s*false` +
		`|default\s+allow\s*:?=?\s*false`,
)

func looksLikeFailsClosed(rego string) bool {
	return failsClosedPattern.MatchString(strings.TrimSpace(rego))
}
