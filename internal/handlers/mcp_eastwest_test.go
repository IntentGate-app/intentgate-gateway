package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/capability"
)

// eastWestCapHandler returns a handler with only the fields
// runCapabilityCheck reads: a master key to verify the token. Revocation and
// kill switch are nil, so those gates are skipped and the test isolates the
// north-south-scope-vs-east-west decision. testMaster is defined in
// mcp_provenance_test.go (same package).
func eastWestCapHandler() *mcpHandler {
	return &mcpHandler{cfg: MCPHandlerConfig{
		Logger:    slog.Default(),
		MasterKey: testMaster,
	}}
}

// reqWithToken builds a request carrying the encoded capability token in the
// Authorization header, the way a real MCP tools/call arrives.
func reqWithToken(t *testing.T, tok *capability.Token) *http.Request {
	t.Helper()
	enc, err := tok.Encode()
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+enc)
	return r
}

// mintScoped mints a token bound to subject, scoped to a single north-south
// tool ("read_invoice"), so an east-west target like "agent:finance" is
// deliberately out of north-south scope.
func mintScoped(t *testing.T, subject string, expiry time.Time) *capability.Token {
	t.Helper()
	tok, err := capability.Mint(testMaster, capability.MintOptions{
		Subject: subject,
		Zone:    "control",
		Expiry:  expiry,
		Caveats: []capability.Caveat{
			{Type: capability.CaveatToolWhitelist, Tools: []string{"read_invoice"}},
		},
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestCapabilityCheck_EastWestDefersNorthSouthScope(t *testing.T) {
	h := eastWestCapHandler()
	tok := mintScoped(t, "orchestrator", time.Time{})

	// North-south: the callee agent-tool is not in the whitelist, so a
	// non-east-west check rejects it. This is the pilot's over-block: it
	// pre-empted east-west at Check 1.
	if res := h.runCapabilityCheck(reqWithToken(t, tok), "agent:finance", false); res.err == nil {
		t.Fatal("north-south check should reject an out-of-scope tool")
	}

	// East-west: the same call, flagged agent-to-agent, defers north-south
	// scope to the east-west policy, so the capability stage passes. The
	// token is still verified and carried forward.
	res := h.runCapabilityCheck(reqWithToken(t, tok), "agent:finance", true)
	if res.err != nil {
		t.Fatalf("east-west call must not be blocked by north-south scope: %v", res.err)
	}
	if res.token == nil || res.agentID != "orchestrator" {
		t.Fatalf("east-west pass should still carry the verified token, got %+v", res)
	}
}

func TestCapabilityCheck_NorthSouthScopeStillEnforced(t *testing.T) {
	// Regression: an ordinary tool call is still gated by the whitelist, so
	// deferring scope for east-west did not weaken north-south enforcement.
	h := eastWestCapHandler()
	tok := mintScoped(t, "orchestrator", time.Time{})

	if res := h.runCapabilityCheck(reqWithToken(t, tok), "read_invoice", false); res.err != nil {
		t.Fatalf("in-scope tool should pass: %v", res.err)
	}
	if res := h.runCapabilityCheck(reqWithToken(t, tok), "delete_everything", false); res.err == nil {
		t.Fatal("out-of-scope north-south tool must be blocked")
	}
}

func TestCapabilityCheck_EastWestStillEnforcesValidity(t *testing.T) {
	// The east-west scope deferral skips only the tool whitelist/blacklist.
	// Every other caveat still applies, so an expired token is rejected even
	// on the east-west path.
	h := eastWestCapHandler()
	expired := mintScoped(t, "orchestrator", time.Now().Add(-time.Hour))

	if res := h.runCapabilityCheck(reqWithToken(t, expired), "agent:finance", true); res.err == nil {
		t.Fatal("expired token must be rejected even on the east-west path")
	}
}

func TestCapabilityCheck_EastWestStillEnforcesAgentLock(t *testing.T) {
	// The agent-lock caveat is not a tool-scope caveat, so it must still bind
	// an east-west call to the token's subject. We assert the token verifies
	// and its subject is what the east-west stage will use downstream.
	h := eastWestCapHandler()
	tok := mintScoped(t, "orchestrator", time.Time{})

	res := h.runCapabilityCheck(reqWithToken(t, tok), "agent:finance", true)
	if res.err != nil {
		t.Fatalf("valid east-west call should pass: %v", res.err)
	}
	if res.token.Subject != "orchestrator" {
		t.Fatalf("agent-lock subject must be preserved, got %q", res.token.Subject)
	}
}
