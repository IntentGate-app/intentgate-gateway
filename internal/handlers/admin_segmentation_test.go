package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
	"github.com/IntentGate-app/intentgate-gateway/internal/zonescope"
)

func TestAdminSegmentation_Auth(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
	}
	h := NewAdminSegmentationHandler(cfg)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/admin/segmentation", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", rr.Code)
	}
}

// With no guards configured the endpoint returns a disabled state, not a 404.
func TestAdminSegmentation_Disabled(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
	}
	h := NewAdminSegmentationHandler(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/segmentation", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp segmentationConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.EastWest.Enabled || resp.ZoneScope.Enabled {
		t.Fatalf("expected disabled, got %+v", resp)
	}
}

// With guards configured the endpoint reflects their live config.
func TestAdminSegmentation_ReflectsConfig(t *testing.T) {
	ew := eastwest.New(eastwest.Config{
		AgentToolPrefix: "agent:",
		AllowIntraZone:  true,
		Zones:           map[string]string{"agent-finance": "finance"},
		AllowedEdges:    [][2]string{{"procurement", "finance"}},
	})
	zs := zonescope.New(zonescope.Config{
		Scopes: map[string]zonescope.Scope{
			"support": {Tools: []string{"read_invoice"}},
		},
	})
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		EastWest:   ew,
		ZoneScope:  zs,
	}
	h := NewAdminSegmentationHandler(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/segmentation", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp segmentationConfig
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.EastWest.Enabled || resp.EastWest.Zones["agent-finance"] != "finance" {
		t.Fatalf("east-west not reflected: %+v", resp.EastWest)
	}
	if len(resp.EastWest.AllowedEdges) != 1 || resp.EastWest.AllowedEdges[0] != [2]string{"procurement", "finance"} {
		t.Fatalf("edges not reflected: %+v", resp.EastWest.AllowedEdges)
	}
	if !resp.ZoneScope.Enabled {
		t.Fatalf("zone-scope not enabled: %+v", resp.ZoneScope)
	}
	if got := resp.ZoneScope.Scopes["support"].Tools; len(got) != 1 || got[0] != "read_invoice" {
		t.Fatalf("zone-scope tools not reflected: %v", got)
	}
}

// PUT with no configured paths is rejected.
func TestAdminSegmentationWrite_NoPath(t *testing.T) {
	cfg := AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
	}
	h := NewAdminSegmentationWriteHandler(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/segmentation",
		strings.NewReader(`{"east_west":{},"zone_scope":{}}`))
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 (no path), got %d", rr.Code)
	}
}

// PUT persists the submitted config to the configured files.
func TestAdminSegmentationWrite_Persists(t *testing.T) {
	dir := t.TempDir()
	ewPath := filepath.Join(dir, "eastwest.json")
	zsPath := filepath.Join(dir, "zonescope.json")
	cfg := AdminConfig{
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:          "secret",
		EastWestConfigPath:  ewPath,
		ZoneScopeConfigPath: zsPath,
	}
	h := NewAdminSegmentationWriteHandler(cfg)

	bodyJSON := `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "allow_intra_zone": true,
	    "zones": {"agent-finance": "finance"},
	    "allowed_edges": [["procurement", "finance"]]
	  },
	  "zone_scope": {
	    "scopes": {"support": {"tools": ["read_invoice"]}}
	  }
	}`
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/segmentation",
		strings.NewReader(bodyJSON))
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	// The written east-west file must load back into a working guard.
	raw, err := os.ReadFile(ewPath)
	if err != nil {
		t.Fatalf("read written east-west config: %v", err)
	}
	var ewFile struct {
		AgentToolPrefix string            `json:"agent_tool_prefix"`
		AllowIntraZone  bool              `json:"allow_intra_zone"`
		Zones           map[string]string `json:"zones"`
		AllowedEdges    [][2]string       `json:"allowed_edges"`
	}
	if err := json.Unmarshal(raw, &ewFile); err != nil {
		t.Fatalf("written east-west config is not valid JSON: %v", err)
	}
	if ewFile.Zones["agent-finance"] != "finance" || len(ewFile.AllowedEdges) != 1 {
		t.Fatalf("written east-west config wrong: %+v", ewFile)
	}
	g := eastwest.New(eastwest.Config{
		AgentToolPrefix: ewFile.AgentToolPrefix,
		AllowIntraZone:  ewFile.AllowIntraZone,
		Zones:           ewFile.Zones,
		AllowedEdges:    ewFile.AllowedEdges,
	})
	if r := g.Check("agent-x", "procurement", "agent:agent-finance"); r.Verdict != eastwest.VerdictAllow {
		t.Fatalf("round-tripped config should allow procurement->finance, got %s", r.Verdict)
	}

	// The zone-scope file too.
	rawZS, err := os.ReadFile(zsPath)
	if err != nil {
		t.Fatalf("read written zone-scope config: %v", err)
	}
	if !strings.Contains(string(rawZS), "read_invoice") {
		t.Fatalf("zone-scope config missing tool: %s", rawZS)
	}
}

// The draft endpoint parses plain language into a segmentation config.
func TestAdminSegmentationDraft(t *testing.T) {
	cfg := AdminConfig{
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:      "secret",
		AgentToolPrefix: "agent:",
	}
	h := NewAdminSegmentationDraftHandler(cfg)

	text := "zone finance: agent-ledger\nprocurement may call finance\nfinance may use read_invoice\nallow intra-zone"
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/segmentation/draft",
		strings.NewReader(`{"text":`+jsonString(text)+`}`))
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var resp struct {
		Draft    segmentationConfig `json:"draft"`
		Warnings []string           `json:"warnings"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Draft.EastWest.Zones["agent-ledger"] != "finance" {
		t.Fatalf("zones not drafted: %+v", resp.Draft.EastWest.Zones)
	}
	if len(resp.Draft.EastWest.AllowedEdges) != 1 || resp.Draft.EastWest.AllowedEdges[0] != [2]string{"procurement", "finance"} {
		t.Fatalf("edges not drafted: %+v", resp.Draft.EastWest.AllowedEdges)
	}
	if !resp.Draft.EastWest.AllowIntraZone {
		t.Fatal("intra-zone not drafted")
	}
	if got := resp.Draft.ZoneScope.Scopes["finance"].Tools; len(got) != 1 || got[0] != "read_invoice" {
		t.Fatalf("scope not drafted: %v", got)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A per-tenant admin may not write global segmentation config.
func TestAdminSegmentationWrite_TenantForbidden(t *testing.T) {
	dir := t.TempDir()
	cfg := AdminConfig{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		TenantAdmins:       map[string]string{"acme": "acme-token"},
		EastWestConfigPath: filepath.Join(dir, "eastwest.json"),
	}
	h := NewAdminSegmentationWriteHandler(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/segmentation",
		strings.NewReader(`{"east_west":{},"zone_scope":{}}`))
	req.Header.Set("Authorization", "Bearer acme-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("want 403 for per-tenant admin, got %d", rr.Code)
	}
}
