package eastwest

import "testing"

// A base config: three zones, one permitted direction (procurement may call
// finance), intra-zone allowed.
func base() Config {
	return Config{
		AgentToolPrefix: "agent:",
		Zones: map[string]string{
			"agent-procure":  "procurement",
			"agent-finance":  "finance",
			"agent-budget":   "finance",
			"agent-support":  "support",
			"agent-readonly": "support",
		},
		AllowedEdges:   [][2]string{{"procurement", "finance"}},
		AllowIntraZone: true,
	}
}

// An ordinary tool call is not an east-west call and must pass through untouched.
func TestCheck_NonAgentToolIsNoOp(t *testing.T) {
	g := New(base())
	r := g.Check("agent-procure", "", "transfer_funds")
	if r.EastWest {
		t.Fatalf("transfer_funds should not be treated as east-west")
	}
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (pass-through)", r.Verdict)
	}
}

// A permitted zone-to-zone direction is allowed.
func TestCheck_AllowedEdge(t *testing.T) {
	g := New(base())
	r := g.Check("agent-procure", "", "agent:agent-finance")
	if !r.EastWest {
		t.Fatalf("should be an east-west call")
	}
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (%s)", r.Verdict, r.Reason)
	}
	if r.CalleeAgent != "agent-finance" || r.CalleeZone != "finance" {
		t.Fatalf("callee=%q zone=%q", r.CalleeAgent, r.CalleeZone)
	}
}

// The reverse direction is not permitted just because the forward one is.
func TestCheck_DirectionMatters(t *testing.T) {
	g := New(base())
	r := g.Check("agent-finance", "", "agent:agent-procure")
	if r.Verdict != VerdictDeny {
		t.Fatalf("finance->procurement should be denied, got %s", r.Verdict)
	}
}

// No edge and different zones: default-deny. This is the containment case,
// a support agent cannot recruit a finance agent.
func TestCheck_DefaultDenyCrossZone(t *testing.T) {
	g := New(base())
	r := g.Check("agent-support", "", "agent:agent-finance")
	if r.Verdict != VerdictDeny {
		t.Fatalf("support->finance should be denied (default-deny), got %s", r.Verdict)
	}
}

// Agents in the same zone may call each other when intra-zone is allowed.
func TestCheck_IntraZoneAllowed(t *testing.T) {
	g := New(base())
	r := g.Check("agent-finance", "", "agent:agent-budget") // both in finance
	if r.Verdict != VerdictAllow {
		t.Fatalf("intra-zone finance call should be allowed, got %s (%s)", r.Verdict, r.Reason)
	}
}

// With intra-zone disabled, same-zone calls need an explicit edge too.
func TestCheck_IntraZoneDeniedWhenOff(t *testing.T) {
	cfg := base()
	cfg.AllowIntraZone = false
	g := New(cfg)
	r := g.Check("agent-finance", "", "agent:agent-budget")
	if r.Verdict != VerdictDeny {
		t.Fatalf("intra-zone call should be denied when AllowIntraZone is false, got %s", r.Verdict)
	}
}

// An agent with no zone is in the empty zone and cannot reach a zoned agent
// unless an explicit edge from "" exists.
func TestCheck_UnknownZoneDenied(t *testing.T) {
	g := New(base())
	r := g.Check("agent-unknown", "", "agent:agent-finance")
	if r.Verdict != VerdictDeny {
		t.Fatalf("unknown-zone caller should be denied, got %s", r.Verdict)
	}
}

// The caller's zone from its signed token is authoritative and overrides the
// config directory. Here the config places the caller in "support" (which may
// not reach finance), but the token says "procurement" (which may). The token
// wins, so the call is allowed. This makes the zone travel with identity and
// stops a stale or missing config entry from breaking a legitimately-zoned
// agent.
func TestCheck_TokenZoneOverridesConfig(t *testing.T) {
	g := New(base())
	r := g.Check("agent-support", "procurement", "agent:agent-finance")
	if r.Verdict != VerdictAllow {
		t.Fatalf("token zone procurement->finance should be allowed, got %s (%s)", r.Verdict, r.Reason)
	}
	if r.CallerZone != "procurement" {
		t.Fatalf("caller zone = %q, want procurement (from token)", r.CallerZone)
	}
}

// The reverse: the token authoritatively places the caller somewhere with no
// path, so even a caller the config would have allowed is denied.
func TestCheck_TokenZoneDeniesWhenNoPath(t *testing.T) {
	g := New(base())
	// Config would put agent-procure in procurement (procurement->finance ok),
	// but the token says support, which has no path to finance.
	r := g.Check("agent-procure", "support", "agent:agent-finance")
	if r.Verdict != VerdictDeny {
		t.Fatalf("token zone support->finance should be denied, got %s", r.Verdict)
	}
}

// With no config entry for the caller at all, the token zone is what places it.
func TestCheck_TokenZoneUsedWithoutConfigEntry(t *testing.T) {
	g := New(base())
	r := g.Check("agent-brand-new", "procurement", "agent:agent-finance")
	if r.Verdict != VerdictAllow {
		t.Fatalf("uncatalogued caller with token zone procurement should reach finance, got %s (%s)", r.Verdict, r.Reason)
	}
}

// Empty prefix disables east-west detection entirely: everything is a no-op.
func TestCheck_EmptyPrefixDisables(t *testing.T) {
	cfg := base()
	cfg.AgentToolPrefix = ""
	g := New(cfg)
	r := g.Check("agent-support", "", "agent:agent-finance")
	if r.EastWest || r.Verdict != VerdictAllow {
		t.Fatalf("with no prefix, nothing is east-west; got EastWest=%v verdict=%s", r.EastWest, r.Verdict)
	}
}

// CalleeAgent parses the target id and rejects a bare prefix.
func TestCalleeAgent(t *testing.T) {
	g := New(base())
	if c, ok := g.CalleeAgent("agent:agent-finance"); !ok || c != "agent-finance" {
		t.Fatalf("callee=%q ok=%v", c, ok)
	}
	if _, ok := g.CalleeAgent("agent:"); ok {
		t.Fatalf("bare prefix must not be a valid agent target")
	}
	if _, ok := g.CalleeAgent("read_invoice"); ok {
		t.Fatalf("ordinary tool must not be an agent target")
	}
}

// --- Per-agent rules ------------------------------------------------------
//
// The unit of control is one named caller calling one named callee. These
// tests pin that a rule about two agents decides on its own, with no label
// involved, and that sharing a label still grants nothing.

// A rule naming two agents permits exactly that pair, with no labels at all.
func TestCheck_AgentRule_ExactPair(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-1", "agent-finance-1"}},
	})
	r := g.Check("agent-procure-1", "", "agent:agent-finance-1")
	if r.Verdict != VerdictAllow {
		t.Fatalf("named pair should be allowed, got %s (%s)", r.Verdict, r.Reason)
	}
	if r.DecidedBy != "agent-rule" {
		t.Fatalf("DecidedBy = %q, want agent-rule", r.DecidedBy)
	}
}

// The rule is directional: naming a -> b must not permit b -> a.
func TestCheck_AgentRule_IsDirectional(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-1", "agent-finance-1"}},
	})
	r := g.Check("agent-finance-1", "", "agent:agent-procure-1")
	if r.Verdict != VerdictDeny {
		t.Fatalf("reverse direction must be denied, got %s (%s)", r.Verdict, r.Reason)
	}
}

// A rule about one pair must not leak to a sibling that no rule names.
func TestCheck_AgentRule_DoesNotCoverSiblings(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-1", "agent-finance-1"}},
	})
	r := g.Check("agent-procure-1", "", "agent:agent-finance-2")
	if r.Verdict != VerdictDeny {
		t.Fatalf("unnamed callee must be denied, got %s (%s)", r.Verdict, r.Reason)
	}
	r2 := g.Check("agent-procure-2", "", "agent:agent-finance-1")
	if r2.Verdict != VerdictDeny {
		t.Fatalf("unnamed caller must be denied, got %s (%s)", r2.Verdict, r2.Reason)
	}
}

// A trailing-* pattern writes a fleet rule without listing every member.
func TestCheck_AgentRule_Pattern(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-procure-*", "agent-finance-1"}},
	})
	for _, caller := range []string{"agent-procure-1", "agent-procure-9"} {
		if r := g.Check(caller, "", "agent:agent-finance-1"); r.Verdict != VerdictAllow {
			t.Fatalf("%s should match the pattern, got %s (%s)", caller, r.Verdict, r.Reason)
		}
	}
	if r := g.Check("agent-support-1", "", "agent:agent-finance-1"); r.Verdict != VerdictDeny {
		t.Fatalf("non-matching caller must be denied, got %s (%s)", r.Verdict, r.Reason)
	}
}

// Sharing a label grants nothing on its own. This is the property that
// separates per-agent control from group segmentation.
func TestCheck_SharedLabelGrantsNothing(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		Zones: map[string]string{
			"agent-finance-1": "finance",
			"agent-finance-2": "finance",
		},
		AllowIntraZone: false,
	})
	r := g.Check("agent-finance-1", "", "agent:agent-finance-2")
	if r.Verdict != VerdictDeny {
		t.Fatalf("same label must not imply a path, got %s (%s)", r.Verdict, r.Reason)
	}
	if r.DecidedBy != "default-deny" {
		t.Fatalf("DecidedBy = %q, want default-deny", r.DecidedBy)
	}
}

// An agent rule works even when neither agent carries a label, so labels are
// genuinely optional rather than a hidden prerequisite.
func TestCheck_AgentRule_NeedsNoLabels(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-a", "agent-b"}},
	})
	r := g.Check("agent-a", "", "agent:agent-b")
	if r.Verdict != VerdictAllow {
		t.Fatalf("unlabelled pair with a rule should be allowed, got %s (%s)", r.Verdict, r.Reason)
	}
	if r.CalleeUnzoned {
		t.Fatalf("CalleeUnzoned must not be set when a rule decided the call")
	}
}

// When a label rule decides the call, the audit says so, so a reviewer can
// tell a per-agent authorisation from a group-level one.
func TestCheck_LabelRuleIsReportedAsSuch(t *testing.T) {
	g := New(base())
	r := g.Check("agent-procure", "", "agent:agent-finance")
	if r.Verdict != VerdictAllow {
		t.Fatalf("label rule should still allow, got %s (%s)", r.Verdict, r.Reason)
	}
	if r.DecidedBy != "label-rule" {
		t.Fatalf("DecidedBy = %q, want label-rule", r.DecidedBy)
	}
}

// --- Observe mode ---------------------------------------------------------

// Observe mode lets an unruled call through and flags it, so an estate can be
// watched before it is enforced. Without this there is no safe way to start:
// the recommender learns from allowed traffic, and a correct default-deny
// estate produces none.
func TestCheck_ObserveMode_AllowsAndFlags(t *testing.T) {
	g := New(Config{AgentToolPrefix: "agent:", ObserveOnly: true})
	r := g.Check("agent-a", "", "agent:agent-b")
	if r.Verdict != VerdictAllow {
		t.Fatalf("observe mode must not block, got %s (%s)", r.Verdict, r.Reason)
	}
	if !r.WouldDeny {
		t.Fatal("observe mode must flag WouldDeny so the call is recoverable from the audit")
	}
	if r.DecidedBy != "observe-only" {
		t.Fatalf("DecidedBy = %q, want observe-only", r.DecidedBy)
	}
}

// A call a rule already permits is a real allow, not an observation, even with
// observe mode on. Otherwise the operator could not tell which paths are
// already covered from which still need a rule.
func TestCheck_ObserveMode_RuledCallIsNotFlagged(t *testing.T) {
	g := New(Config{
		AgentToolPrefix: "agent:",
		ObserveOnly:     true,
		AllowedPairs:    [][2]string{{"agent-a", "agent-b"}},
	})
	r := g.Check("agent-a", "", "agent:agent-b")
	if r.Verdict != VerdictAllow || r.WouldDeny {
		t.Fatalf("ruled call should be a plain allow, got %s WouldDeny=%v", r.Verdict, r.WouldDeny)
	}
	if r.DecidedBy != "agent-rule" {
		t.Fatalf("DecidedBy = %q, want agent-rule", r.DecidedBy)
	}
}

// Turning observe mode off must enforce, with no residue.
func TestCheck_ObserveModeOff_Enforces(t *testing.T) {
	g := New(Config{AgentToolPrefix: "agent:", ObserveOnly: false})
	r := g.Check("agent-a", "", "agent:agent-b")
	if r.Verdict != VerdictDeny || r.WouldDeny {
		t.Fatalf("enforcement expected, got %s WouldDeny=%v", r.Verdict, r.WouldDeny)
	}
}

// Replace swaps the ruleset live, which is what lets the console apply a
// change without a restart.
func TestReplace_SwapsRulesLive(t *testing.T) {
	g := New(Config{AgentToolPrefix: "agent:"})
	if r := g.Check("agent-a", "", "agent:agent-b"); r.Verdict != VerdictDeny {
		t.Fatalf("expected deny before the rule exists, got %s", r.Verdict)
	}
	g.Replace(Config{
		AgentToolPrefix: "agent:",
		AllowedPairs:    [][2]string{{"agent-a", "agent-b"}},
	})
	if r := g.Check("agent-a", "", "agent:agent-b"); r.Verdict != VerdictAllow {
		t.Fatalf("expected allow after Replace, got %s (%s)", r.Verdict, r.Reason)
	}
}
