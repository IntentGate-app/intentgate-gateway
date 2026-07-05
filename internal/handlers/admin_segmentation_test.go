package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
