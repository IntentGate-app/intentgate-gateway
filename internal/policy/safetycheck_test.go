package policy

import "testing"

func find(r Report, code string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.Code == code {
			return f, true
		}
	}
	return Finding{}, false
}

const failsClosed = `package intentgate.policy
default decision := {"allow": false, "reason": "default deny"}`

const failsOpen = `package intentgate.policy
default decision := {"allow": true, "reason": "default allow"}`

// The headline case: a change that denies most of what's currently
// allowed. This is the fat-finger the whole checker exists to catch.
func TestMassBlockIsCritical(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 1000, CandidateBlock: 500, AllowToBlock: 500}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	f, ok := find(r, "mass_block")
	if !ok {
		t.Fatal("mass block not flagged")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("50%% block should be critical, got %s", f.Severity)
	}
	if !r.Blocking {
		t.Error("report should be blocking when a critical finding exists")
	}
	if !r.Tested {
		t.Error("report should be marked tested when events were evaluated")
	}
}

// A moderate block is worth a warning but not a block.
func TestModerateBlockIsWarning(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 1000, CandidateBlock: 150, AllowToBlock: 150}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	f, ok := find(r, "mass_block")
	if !ok {
		t.Fatal("15% block not flagged")
	}
	if f.Severity != SeverityWarning {
		t.Errorf("15%% should warn, got %s", f.Severity)
	}
	if r.Blocking {
		t.Error("a warning should not make the report blocking")
	}
}

// Opening traffic that was blocked trips sooner than blocking — a
// policy that stops enforcing is the quiet, dangerous kind.
func TestMassAllowTripsSoonerThanBlock(t *testing.T) {
	// 8% would not trip the block threshold (10%) but must trip allow (5%).
	s := DryRunSummary{EventsEvaluated: 1000, CandidateAllow: 900, CandidateBlock: 20, BlockToAllow: 80}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	if _, ok := find(r, "mass_allow"); !ok {
		t.Fatal("8% opening-up not flagged, but the allow threshold is 5%")
	}
}

// Errors on real traffic are always critical.
func TestPolicyErrorIsCritical(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 1000, CandidateBlock: 10, PolicyError: 4, CandidateAllow: 986}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	f, ok := find(r, "policy_error")
	if !ok || f.Severity != SeverityCritical {
		t.Fatalf("policy errors must be critical: %+v", r.Findings)
	}
}

// A policy that denied nothing across real traffic is the fingerprint
// of one that fails open or was gutted.
func TestAllowsEverythingIsCritical(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 500, CandidateAllow: 500}
	r := Analyze(failsClosed, failsOpen, s, DefaultThresholds())
	f, ok := find(r, "allows_everything")
	if !ok || f.Severity != SeverityCritical {
		t.Fatalf("a deny-nothing policy must be critical: %+v", r.Findings)
	}
}

// The single most important guarantee: no traffic means "not checked",
// never "safe". A caller must be able to tell the two apart.
func TestNoTrafficIsNotSafe(t *testing.T) {
	r := Analyze(failsClosed, failsClosed, DryRunSummary{EventsEvaluated: 0}, DefaultThresholds())
	if r.Tested {
		t.Error("Tested must be false with zero events")
	}
	if _, ok := find(r, "not_tested"); !ok {
		t.Error("a zero-traffic check must say so, not stay silent")
	}
	// And it must not have emitted a mass-block/allow finding off zero data.
	if _, ok := find(r, "mass_block"); ok {
		t.Error("no traffic-based finding should appear with zero events")
	}
}

// A change identical in effect to the current policy is flagged as
// "no change" — usually the wrong draft was selected.
func TestNoChangeIsFlagged(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 1000, CandidateAllow: 900, CandidateBlock: 100}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	if _, ok := find(r, "no_change"); !ok {
		t.Errorf("identical decisions should be flagged: %+v", r.Findings)
	}
}

// Removing the default-deny is a warning, never a false critical — the
// static check is a heuristic and must not train operators to ignore it.
func TestRemovedDefaultDenyWarns(t *testing.T) {
	// Give it traffic that blocks something, so allows_everything doesn't
	// fire and we isolate the static check.
	s := DryRunSummary{EventsEvaluated: 1000, CandidateAllow: 900, CandidateBlock: 100}
	r := Analyze(failsClosed, failsOpen, s, DefaultThresholds())
	f, ok := find(r, "maybe_removed_default_deny")
	if !ok {
		t.Fatalf("removing the default-deny should warn: %+v", r.Findings)
	}
	if f.Severity != SeverityWarning {
		t.Errorf("a text heuristic must not be critical, got %s", f.Severity)
	}
	if f.Suggestion == "" {
		t.Error("this finding has an unambiguous fix and should suggest it")
	}
}

// A clean change against real traffic produces a tested, non-blocking,
// finding-free report. The happy path has to actually be clean, or the
// checker cries wolf and gets ignored.
func TestCleanChangeIsQuiet(t *testing.T) {
	s := DryRunSummary{EventsEvaluated: 10000, CandidateAllow: 9800, CandidateBlock: 200, AllowToBlock: 5, BlockToAllow: 2}
	r := Analyze(failsClosed, failsClosed, s, DefaultThresholds())
	if r.Blocking {
		t.Errorf("a small clean change should not block: %+v", r.Findings)
	}
	if !r.Tested {
		t.Error("should be marked tested")
	}
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical || f.Severity == SeverityWarning {
			t.Errorf("clean change raised %s: %s", f.Severity, f.Code)
		}
	}
}
