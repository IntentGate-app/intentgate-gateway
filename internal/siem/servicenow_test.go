package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// capturedReq is one record the fake ServiceNow instance received.
type capturedReq struct {
	path string
	auth string
	body map[string]any
}

// fakeServiceNow stands in for a ServiceNow instance: it answers the
// OAuth token endpoint and records every Table API POST.
func fakeServiceNow(t *testing.T) (*httptest.Server, *[]capturedReq, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var got []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth_token.do" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"tok-123","expires_in":1800,"token_type":"Bearer"}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/now/table/") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			got = append(got, capturedReq{path: r.URL.Path, auth: r.Header.Get("Authorization"), body: body})
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"result":{"sys_id":"abc"}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &got, &mu
}

func TestServiceNowGRCMappingAndFilter(t *testing.T) {
	srv, got, mu := fakeServiceNow(t)

	sn, err := NewServiceNowEmitter(ServiceNowConfig{
		InstanceURL:        srv.URL,
		Target:             TargetGRC,
		Username:           "svc",
		Password:           "pw",
		IncludeProofHashes: true,
		// IncludeAllows defaults false → allows must be dropped.
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// An allow (should be filtered out) and a block (should be posted).
	sn.Emit(context.Background(), audit.Event{Decision: audit.DecisionAllow, Tool: "read_invoice", AgentID: "agent-1"})
	sn.Emit(context.Background(), audit.Event{Decision: audit.DecisionBlock, Tool: "transfer_funds", AgentID: "agent-finance-1", ResultSHA256: "deadbeef"})

	if err := sn.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("want exactly 1 posted record (block only; allow filtered), got %d", len(*got))
	}
	rec := (*got)[0]
	if rec.path != "/api/now/table/sn_compliance_evidence" {
		t.Errorf("wrong table path: %s", rec.path)
	}
	if !strings.HasPrefix(rec.auth, "Basic ") {
		t.Errorf("want basic auth, got %q", rec.auth)
	}
	if s, _ := rec.body["short_description"].(string); !strings.Contains(s, "transfer_funds") || !strings.Contains(s, "agent-finance-1") {
		t.Errorf("short_description missing agent/tool: %q", s)
	}
	if st, _ := rec.body["state"].(string); st != "Issue Generated" {
		t.Errorf("want state 'Issue Generated' for block, got %q", st)
	}
	if at, _ := rec.body["attestation_type"].(string); at != "Automated Evidence" {
		t.Errorf("want attestation_type 'Automated Evidence', got %q", at)
	}
}

func TestServiceNowOAuthAndMinSeverity(t *testing.T) {
	srv, got, mu := fakeServiceNow(t)

	sn, err := NewServiceNowEmitter(ServiceNowConfig{
		InstanceURL:  srv.URL,
		Target:       TargetITSM,
		ClientID:     "cid",
		ClientSecret: "secret",
		MinSeverity:  "high", // only blocks pass
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	// Escalate is medium severity → filtered by MinSeverity=high.
	sn.Emit(context.Background(), audit.Event{Decision: audit.DecisionEscalate, Tool: "db_delete", AgentID: "agent-2"})
	// Block is high → passes.
	sn.Emit(context.Background(), audit.Event{Decision: audit.DecisionBlock, Tool: "db_delete", AgentID: "agent-2"})

	if err := sn.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 1 {
		t.Fatalf("want 1 record (block only; escalate below MinSeverity), got %d", len(*got))
	}
	rec := (*got)[0]
	if rec.path != "/api/now/table/incident" {
		t.Errorf("wrong ITSM table path: %s", rec.path)
	}
	if rec.auth != "Bearer tok-123" {
		t.Errorf("want oauth bearer token, got %q", rec.auth)
	}
}

func TestServiceNowConfigValidation(t *testing.T) {
	// custom target with no table must error.
	if _, err := NewServiceNowEmitter(ServiceNowConfig{InstanceURL: "https://x", Target: TargetCustom, Username: "u", Password: "p"}); err == nil {
		t.Error("want error for custom target without Table")
	}
	// no auth must error.
	if _, err := NewServiceNowEmitter(ServiceNowConfig{InstanceURL: "https://x"}); err == nil {
		t.Error("want error when no auth is set")
	}
	// happy path (basic) must succeed and be stoppable.
	sn, err := NewServiceNowEmitter(ServiceNowConfig{InstanceURL: "https://x", Username: "u", Password: "p"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = sn.Stop(context.Background())
}
