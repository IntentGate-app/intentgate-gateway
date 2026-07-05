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
