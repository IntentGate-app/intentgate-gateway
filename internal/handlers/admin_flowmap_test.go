package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/auditstore"
	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
	"github.com/IntentGate-app/intentgate-gateway/internal/flowmap"
)

func flowMapStore(t *testing.T) auditstore.Store {
	t.Helper()
	s := auditstore.NewMemoryStore(100)
	now := time.Now().UTC()
	mk := func(d time.Duration, decision audit.Decision, tool, agent, tenant string) audit.Event {
		e := audit.NewEvent(decision, tool)
		e.Timestamp = now.Add(d).Format(time.RFC3339Nano)
		e.AgentID = agent
		e.Tenant = tenant
		return e
	}
	for _, e := range []audit.Event{
		mk(0, audit.DecisionAllow, "read_invoice", "agent-finance", "acme"),
		mk(time.Second, audit.DecisionAllow, "read_invoice", "agent-finance", "acme"),
		mk(2*time.Second, audit.DecisionBlock, "agent:agent-finance", "agent-support", "acme"),
	} {
		if err := s.Insert(context.Background(), e); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}
	return s
}

func TestAdminFlowMap_Auth(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		AuditStore: flowMapStore(t),
	}
	h := NewAdminFlowMapHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/flow-map", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rr.Code)
	}
}

func TestAdminFlowMap_ExtractsGraph(t *testing.T) {
	cfg := AdminConfig{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:      "secret",
		AuditStore:      flowMapStore(t),
		AgentToolPrefix: "agent:",
	}
	h := NewAdminFlowMapHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/flow-map", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Graph   flowmap.Graph `json:"graph"`
		Sampled int           `json:"sampled"`
		Limit   int           `json:"limit"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Sampled != 3 {
		t.Fatalf("sampled = %d, want 3", resp.Sampled)
	}

	// North-south edge finance -> read_invoice with 2 allows.
	var ns, ew *flowmap.Edge
	for i := range resp.Graph.Edges {
		e := &resp.Graph.Edges[i]
		if e.From == "agent-finance" && e.To == "read_invoice" {
			ns = e
		}
		if e.From == "agent-support" && e.To == "agent-finance" {
			ew = e
		}
	}
	if ns == nil || ns.Kind != flowmap.EdgeNorthSouth || ns.Allow != 2 {
		t.Fatalf("north-south edge wrong: %+v", ns)
	}
	// East-west edge support -> finance, derived from the agent: prefix, 1 block.
	if ew == nil || ew.Kind != flowmap.EdgeEastWest || ew.Block != 1 {
		t.Fatalf("east-west edge wrong: %+v", ew)
	}
}

// With the east-west guard configured, the flow-map endpoint annotates each
// east-west edge with the current policy verdict.
func TestAdminFlowMap_PolicyOverlay(t *testing.T) {
	ew := eastwest.New(eastwest.Config{
		AgentToolPrefix: "agent:",
		Zones: map[string]string{
			"agent-support": "support",
			"agent-finance": "finance",
		},
		// No allowed edges: support -> finance is default-denied.
	})
	cfg := AdminConfig{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:      "secret",
		AuditStore:      flowMapStore(t),
		AgentToolPrefix: "agent:",
		EastWest:        ew,
	}
	h := NewAdminFlowMapHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/flow-map", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Graph struct {
			Edges []struct {
				From   string `json:"from"`
				To     string `json:"to"`
				Kind   string `json:"kind"`
				Policy string `json:"policy"`
			} `json:"edges"`
		} `json:"graph"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var found bool
	for _, e := range resp.Graph.Edges {
		if e.From == "agent-support" && e.To == "agent-finance" {
			found = true
			if e.Policy != "deny" {
				t.Fatalf("east-west policy = %q, want deny (default-deny)", e.Policy)
			}
		}
	}
	if !found {
		t.Fatal("east-west edge not present in response")
	}
}

// The recommend endpoint proposes a least-privilege policy from allowed traffic.
func TestAdminFlowRecommend(t *testing.T) {
	ew := eastwest.New(eastwest.Config{
		AgentToolPrefix: "agent:",
		Zones: map[string]string{
			"agent-support": "support",
			"agent-finance": "finance",
		},
	})
	cfg := AdminConfig{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:      "secret",
		AuditStore:      flowMapStore(t),
		AgentToolPrefix: "agent:",
		EastWest:        ew,
	}
	h := NewAdminFlowRecommendHandler(cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/flow-map/recommend", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Recommendation struct {
			AllowedEdges [][2]string         `json:"allowed_edges"`
			ZoneTools    map[string][]string `json:"zone_tools"`
		} `json:"recommendation"`
		ZoneScopeConfig struct {
			Scopes map[string]struct {
				Tools []string `json:"tools"`
			} `json:"scopes"`
		} `json:"zone_scope_config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// finance called read_invoice (allowed x2) -> proposed scope.
	if got := resp.Recommendation.ZoneTools["finance"]; len(got) != 1 || got[0] != "read_invoice" {
		t.Fatalf("finance zone tools = %v, want [read_invoice]", got)
	}
	if got := resp.ZoneScopeConfig.Scopes["finance"].Tools; len(got) != 1 || got[0] != "read_invoice" {
		t.Fatalf("zone_scope_config finance tools = %v, want [read_invoice]", got)
	}
	// The only east-west call (support -> finance) was blocked, so it must not
	// become a recommended edge.
	if len(resp.Recommendation.AllowedEdges) != 0 {
		t.Fatalf("allowed edges = %v, want none (east-west was blocked)", resp.Recommendation.AllowedEdges)
	}
}
