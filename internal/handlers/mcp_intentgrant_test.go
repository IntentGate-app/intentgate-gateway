package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/intentauthz"
	"github.com/IntentGate-app/intentgate-gateway/internal/mcp"
	"github.com/IntentGate-app/intentgate-gateway/internal/upstream"
)

// The product claim, as a test: on ALLOW the toolserver runs exactly once; on any
// DENY — and when the control plane is unreachable — it runs zero times, and the
// caller still gets a decision id + reason. The toolserver never receives the call.

func igToolsCall(name string) []byte {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	b, _ := json.Marshal(mcp.Request{JSONRPC: mcp.Version, ID: json.RawMessage("1"), Method: mcp.MethodToolsCall, Params: params})
	return b
}

// fakePDP is a stand-in control plane returning a fixed decision/reason.
func fakePDP(t *testing.T, decision, reason, decisionID, grant string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rec := map[string]any{"decision_id": decisionID, "reason_code": reason}
		if grant != "" {
			rec["grant_id"] = grant
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": decision, "record": rec})
	}))
	t.Cleanup(s.Close)
	return s
}

// countingUpstream is the toolserver; the counter is the whole point of the sprint.
func countingUpstream(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var n int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&n, 1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"executed"}]}}`))
	}))
	t.Cleanup(s.Close)
	return s, &n
}

func igHandler(t *testing.T, pdpURL, upstreamURL string) http.Handler {
	t.Helper()
	az, err := intentauthz.New(intentauthz.Config{URL: pdpURL})
	if err != nil {
		t.Fatalf("intentauthz.New: %v", err)
	}
	var up *upstream.Client
	if upstreamURL != "" {
		if up, err = upstream.New(upstream.Config{URL: upstreamURL}); err != nil {
			t.Fatalf("upstream.New: %v", err)
		}
	}
	return NewIntentGrantMCPHandler(IntentGrantMCPConfig{Authz: az, Upstream: up})
}

func igCall(t *testing.T, h http.Handler, agent, tool string) *mcp.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/ig", bytes.NewReader(igToolsCall(tool)))
	req.Header.Set("Content-Type", "application/json")
	if agent != "" {
		req.Header.Set(DefaultAgentHeader, agent)
	}
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp mcp.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rec.Body.String())
	}
	return &resp
}

func errData(t *testing.T, resp *mcp.Response) map[string]any {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("expected a JSON-RPC error, got result: %s", resp.Result)
	}
	m, ok := resp.Error.Data.(map[string]any)
	if !ok {
		t.Fatalf("error.data: want map, got %T (%v)", resp.Error.Data, resp.Error.Data)
	}
	return m
}

func TestIntentGrant_Allow_ForwardsToToolserverExactlyOnce(t *testing.T) {
	up, count := countingUpstream(t)
	pdp := fakePDP(t, "ALLOW", "GRANT_ACTIVE", "DEC-000001", "IG-000001")
	h := igHandler(t, pdp.URL, up.URL)

	resp := igCall(t, h, "agent-7", "deploy-tool")

	if resp.Error != nil {
		t.Fatalf("ALLOW should not error: %+v", resp.Error)
	}
	if got := atomic.LoadInt32(count); got != 1 {
		t.Fatalf("toolserver invocations: want 1, got %d", got)
	}
	if !bytes.Contains(resp.Result, []byte("executed")) {
		t.Errorf("downstream result not returned: %s", resp.Result)
	}
}

func TestIntentGrant_Deny_ToolserverNeverInvoked(t *testing.T) {
	for _, reason := range []string{"NO_GRANT", "GRANT_EXPIRED", "GRANT_REVOKED"} {
		t.Run(reason, func(t *testing.T) {
			up, count := countingUpstream(t)
			pdp := fakePDP(t, "DENY", reason, "DEC-000009", "")
			h := igHandler(t, pdp.URL, up.URL)

			resp := igCall(t, h, "agent-7", "deploy-tool")

			// The assertion that matters: the toolserver was never called.
			if got := atomic.LoadInt32(count); got != 0 {
				t.Fatalf("%s: toolserver invocations: want 0, got %d", reason, got)
			}
			if resp.Error == nil || resp.Error.Code != mcp.CodePolicyFailed {
				t.Fatalf("%s: want CodePolicyFailed error, got %+v / result %s", reason, resp.Error, resp.Result)
			}
			data := errData(t, resp)
			if data["reason"] != reason {
				t.Errorf("%s: reason in evidence: want %q, got %v", reason, reason, data["reason"])
			}
			if data["decision_id"] != "DEC-000009" {
				t.Errorf("%s: decision_id missing from deny: got %v", reason, data["decision_id"])
			}
		})
	}
}

func TestIntentGrant_UnknownIdentity_DeniesWithoutInvokingToolserver(t *testing.T) {
	up, count := countingUpstream(t)
	// The control plane could not resolve the agent → NO_GRANT DENY.
	pdp := fakePDP(t, "DENY", "NO_GRANT", "DEC-000010", "")
	h := igHandler(t, pdp.URL, up.URL)

	resp := igCall(t, h, "ghost-agent", "deploy-tool")

	if got := atomic.LoadInt32(count); got != 0 {
		t.Fatalf("toolserver invocations: want 0, got %d", got)
	}
	if resp.Error == nil {
		t.Fatal("unresolved identity must be denied")
	}
}

func TestIntentGrant_MissingAgentHeader_DeniesLocallyWithoutToolserver(t *testing.T) {
	up, count := countingUpstream(t)
	pdp := fakePDP(t, "ALLOW", "GRANT_ACTIVE", "DEC-x", "IG-x") // would allow, but we never reach it
	h := igHandler(t, pdp.URL, up.URL)

	resp := igCall(t, h, "", "deploy-tool") // no X-IntentGate-Agent

	if got := atomic.LoadInt32(count); got != 0 {
		t.Fatalf("toolserver invocations: want 0, got %d", got)
	}
	if resp.Error == nil || resp.Error.Code != mcp.CodeInvalidParams {
		t.Fatalf("want CodeInvalidParams, got %+v", resp.Error)
	}
}

func TestIntentGrant_ControlPlaneUnavailable_FailsClosed(t *testing.T) {
	up, count := countingUpstream(t)
	// A control plane that is down: create then immediately close it so the URL
	// refuses connections. The PEP must fail closed, never forward.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	h := igHandler(t, deadURL, up.URL)
	resp := igCall(t, h, "agent-7", "deploy-tool")

	if got := atomic.LoadInt32(count); got != 0 {
		t.Fatalf("fail-closed violated: toolserver invocations: want 0, got %d", got)
	}
	if resp.Error == nil || resp.Error.Code != mcp.CodeInternalError {
		t.Fatalf("want CodeInternalError (fail closed), got %+v", resp.Error)
	}
	if data := errData(t, resp); data["fail_closed"] != true {
		t.Errorf("expected fail_closed=true in evidence, got %v", data["fail_closed"])
	}
}
