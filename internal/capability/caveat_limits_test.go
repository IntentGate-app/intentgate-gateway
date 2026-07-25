package capability

import "testing"

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewMasterKey()
	if err != nil {
		t.Fatalf("NewMasterKey: %v", err)
	}
	return k
}

func TestRiskMaxCaveat(t *testing.T) {
	key := newKey(t)
	tok, err := Mint(key, MintOptions{Subject: "agent-x", Caveats: []Caveat{{Type: CaveatRiskMax, RiskMax: 70}}})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// Below ceiling → allowed.
	if err := tok.Check(RequestContext{AgentID: "agent-x", Tool: "t", Risk: 40}); err != nil {
		t.Errorf("risk 40 <= 70 should pass: %v", err)
	}
	// Above ceiling → denied.
	if err := tok.Check(RequestContext{AgentID: "agent-x", Tool: "t", Risk: 90}); err == nil {
		t.Error("risk 90 > 70 should be denied")
	}
	// No score (0) → fail open (allowed) by design.
	if err := tok.Check(RequestContext{AgentID: "agent-x", Tool: "t", Risk: 0}); err != nil {
		t.Errorf("risk 0 (no score) should pass: %v", err)
	}
}

func TestRiskMaxZeroCeilingDisabled(t *testing.T) {
	key := newKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "a", Caveats: []Caveat{{Type: CaveatRiskMax, RiskMax: 0}}})
	if err := tok.Check(RequestContext{AgentID: "a", Tool: "t", Risk: 100}); err != nil {
		t.Errorf("ceiling 0 disables the gate; risk 100 should pass: %v", err)
	}
}

func TestRateAndCostCaveatsAccepted(t *testing.T) {
	key := newKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "a", Caveats: []Caveat{
		{Type: CaveatRateLimit, RatePerMin: 25},
		{Type: CaveatMaxCost, MaxCents: 500000},
	}})
	// Informational at the capability stage — enforced later by velocity.
	if err := tok.Check(RequestContext{AgentID: "a", Tool: "t"}); err != nil {
		t.Errorf("rate/cost caveats should pass the capability stage: %v", err)
	}
}

func TestMcpAllowCaveat(t *testing.T) {
	key := newKey(t)
	tok, _ := Mint(key, MintOptions{Subject: "a", Caveats: []Caveat{{Type: CaveatMcpAllow, Servers: []string{"sap", "stripe"}}}})
	if err := tok.Check(RequestContext{AgentID: "a", Tool: "sap.invoice.pay"}); err != nil {
		t.Errorf("sap.invoice.pay belongs to sap and should pass: %v", err)
	}
	if err := tok.Check(RequestContext{AgentID: "a", Tool: "workday.read"}); err == nil {
		t.Error("workday.read is not on an allowed server and should be denied")
	}
	// East-west calls are not gated by server scope.
	if err := tok.Check(RequestContext{AgentID: "a", Tool: "agent:other", EastWest: true}); err != nil {
		t.Errorf("east-west call should skip mcp_allow: %v", err)
	}
}
