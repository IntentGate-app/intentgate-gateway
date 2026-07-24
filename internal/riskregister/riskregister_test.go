package riskregister

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// fakeExporter captures what the aggregator exports.
type fakeExporter struct {
	mu     sync.Mutex
	inds   []RiskIndicator
	issues []RiskIssue
}

func (f *fakeExporter) Name() string { return "fake" }
func (f *fakeExporter) PushIndicators(_ context.Context, inds []RiskIndicator) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inds = append(f.inds, inds...)
	return nil
}
func (f *fakeExporter) OpenIssue(_ context.Context, is RiskIssue) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues = append(f.issues, is)
	return nil
}

func TestAggregatorRollupAndThreshold(t *testing.T) {
	f := &fakeExporter{}
	// Long interval so only Stop() triggers the flush, deterministically.
	a := NewAggregator(f, Config{FlushInterval: time.Hour, BlockThreshold: 2})

	ctx := context.Background()
	emit := func(agent string, d audit.Decision) {
		a.Emit(ctx, audit.Event{AgentID: agent, Tenant: "acme", Decision: d, Reason: "policy X", ResultSHA256: "hash"})
	}
	emit("agent-1", audit.DecisionBlock)
	emit("agent-1", audit.DecisionBlock)
	emit("agent-1", audit.DecisionBlock)
	emit("agent-1", audit.DecisionEscalate)
	emit("agent-2", audit.DecisionAllow)

	if err := a.Stop(ctx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.inds) != 2 {
		t.Fatalf("want 2 agent indicators, got %d", len(f.inds))
	}
	byAgent := map[string]RiskIndicator{}
	for _, r := range f.inds {
		byAgent[r.AgentID] = r
	}
	a1 := byAgent["agent-1"]
	if a1.Deny != 3 || a1.Escalate != 1 || a1.Total != 4 {
		t.Errorf("agent-1 rollup wrong: %+v", a1)
	}
	if a1.BlockRate() < 0.74 || a1.BlockRate() > 0.76 {
		t.Errorf("agent-1 block rate wrong: %v", a1.BlockRate())
	}
	if byAgent["agent-2"].Allow != 1 {
		t.Errorf("agent-2 allow wrong: %+v", byAgent["agent-2"])
	}

	if len(f.issues) != 1 {
		t.Fatalf("want 1 issue (agent-1 over threshold), got %d", len(f.issues))
	}
	if f.issues[0].AgentID != "agent-1" || f.issues[0].DenyCount != 3 {
		t.Errorf("issue wrong: %+v", f.issues[0])
	}
}

func TestAggregatorNoThresholdNoIssue(t *testing.T) {
	f := &fakeExporter{}
	a := NewAggregator(f, Config{FlushInterval: time.Hour, BlockThreshold: 0}) // disabled
	a.Emit(context.Background(), audit.Event{AgentID: "a", Decision: audit.DecisionBlock})
	a.Emit(context.Background(), audit.Event{AgentID: "a", Decision: audit.DecisionBlock})
	_ = a.Stop(context.Background())
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issues) != 0 {
		t.Errorf("threshold disabled, want 0 issues, got %d", len(f.issues))
	}
	if len(f.inds) != 1 {
		t.Errorf("want 1 indicator, got %d", len(f.inds))
	}
}

func TestServiceNowExporter(t *testing.T) {
	var mu sync.Mutex
	got := map[string][]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/now/table/") {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			got[r.URL.Path] = append(got[r.URL.Path], body)
			mu.Unlock()
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				t.Errorf("want basic auth, got %q", r.Header.Get("Authorization"))
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"result":{"sys_id":"x"}}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	exp, err := NewServiceNowExporter(ServiceNowConfig{
		InstanceURL: srv.URL,
		Username:    "svc",
		Password:    "pw",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	err = exp.PushIndicators(context.Background(), []RiskIndicator{{
		Tenant: "acme", AgentID: "agent-1", Allow: 1, Deny: 3, Escalate: 0, Total: 4,
		WindowStart: time.Now().Add(-time.Minute), WindowEnd: time.Now(),
	}})
	if err != nil {
		t.Fatalf("push indicators: %v", err)
	}
	err = exp.OpenIssue(context.Background(), RiskIssue{
		Tenant: "acme", AgentID: "agent-1", Category: "AI runtime policy breach",
		Reason: "policy X", ProofSHA256: "deadbeef", DenyCount: 3,
	})
	if err != nil {
		t.Fatalf("open issue: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	ind := got["/api/now/table/sn_risk_indicator_result"]
	if len(ind) != 1 {
		t.Fatalf("want 1 indicator POST, got %d", len(ind))
	}
	if ind[0]["u_deny"].(float64) != 3 || ind[0]["u_agent_id"] != "agent-1" {
		t.Errorf("indicator body wrong: %+v", ind[0])
	}
	iss := got["/api/now/table/sn_grc_issue"]
	if len(iss) != 1 {
		t.Fatalf("want 1 issue POST, got %d", len(iss))
	}
	if iss[0]["u_proof_sha256"] != "deadbeef" {
		t.Errorf("issue body wrong: %+v", iss[0])
	}
}
