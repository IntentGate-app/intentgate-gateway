package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/killswitch"
	"github.com/IntentGate-app/intentgate-gateway/internal/pii"
)

// replyResp mirrors the handler's JSON response for assertions.
type replyResp struct {
	Action  string         `json:"action"`
	Reply   string         `json:"reply"`
	Counts  map[string]int `json:"counts"`
	Classes []string       `json:"classes"`
	Error   string         `json:"error"`
}

func doReply(t *testing.T, cfg ReplyHandlerConfig, body string) (*httptest.ResponseRecorder, replyResp) {
	t.Helper()
	h := NewReplyHandler(cfg)
	req := httptest.NewRequest(http.MethodPost, "/v1/reply", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out replyResp
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func redactFilter(t *testing.T) *pii.Filter {
	t.Helper()
	f, err := pii.NewFilter(pii.Config{Enabled: true, DefaultAction: pii.ActionRedact})
	if err != nil {
		t.Fatalf("build redact filter: %v", err)
	}
	return f
}

func blockFilter(t *testing.T) *pii.Filter {
	t.Helper()
	f, err := pii.NewFilter(pii.Config{Enabled: true, DefaultAction: pii.ActionBlock})
	if err != nil {
		t.Fatalf("build block filter: %v", err)
	}
	return f
}

func TestReply_NoFilterPassesThrough(t *testing.T) {
	rec, out := doReply(t, ReplyHandlerConfig{}, `{"reply":"hello world"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out.Action != "allow" || out.Reply != "hello world" {
		t.Fatalf("no-filter passthrough: action=%q reply=%q", out.Action, out.Reply)
	}
}

func TestReply_AllowsCleanText(t *testing.T) {
	rec, out := doReply(t,
		ReplyHandlerConfig{ReplyFilter: redactFilter(t)},
		`{"reply":"your order shipped and will arrive tomorrow"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out.Action != "allow" {
		t.Fatalf("clean text should allow, got %q", out.Action)
	}
}

func TestReply_RedactsPII(t *testing.T) {
	rec, out := doReply(t,
		ReplyHandlerConfig{ReplyFilter: redactFilter(t)},
		`{"reply":"sure, email me at john.doe@example.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out.Action != "redact" {
		t.Fatalf("reply with an email should redact, got %q (reply=%q)", out.Action, out.Reply)
	}
	if strings.Contains(out.Reply, "john.doe@example.com") {
		t.Fatalf("redacted reply must not contain the original email: %q", out.Reply)
	}
	if !strings.Contains(out.Reply, "[REDACTED") {
		t.Fatalf("redacted reply should contain a redaction marker: %q", out.Reply)
	}
}

func TestReply_BlocksOnBlockAction(t *testing.T) {
	rec, out := doReply(t,
		ReplyHandlerConfig{ReplyFilter: blockFilter(t)},
		`{"reply":"the customer email is john.doe@example.com"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (block is an inspection outcome, not an HTTP error)", rec.Code)
	}
	if out.Action != "block" {
		t.Fatalf("block-action filter should block, got %q", out.Action)
	}
	if out.Reply != "" {
		t.Fatalf("blocked reply must be empty, got %q", out.Reply)
	}
}

func TestReply_KillSwitchHalts(t *testing.T) {
	ks := killswitch.NewMemoryStore()
	if err := ks.Engage(context.Background(), killswitch.Entry{Type: killswitch.ScopeGlobal, Reason: "incident"}); err != nil {
		t.Fatal(err)
	}
	rec, out := doReply(t,
		ReplyHandlerConfig{ReplyFilter: redactFilter(t), KillSwitch: ks},
		`{"reply":"anything"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if out.Action != "block" {
		t.Fatalf("an engaged global kill must block the reply, got %q", out.Action)
	}
}

func TestReply_RequireCapabilityRejectsMissingToken(t *testing.T) {
	rec, _ := doReply(t,
		ReplyHandlerConfig{RequireCapability: true, ReplyFilter: redactFilter(t)},
		`{"reply":"hello"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token with RequireCapability should be 401, got %d", rec.Code)
	}
}

func TestReply_RejectsBadJSON(t *testing.T) {
	rec, _ := doReply(t,
		ReplyHandlerConfig{ReplyFilter: redactFilter(t)},
		`{"reply": not-json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON should be 400, got %d", rec.Code)
	}
}
