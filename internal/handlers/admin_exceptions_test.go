package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func exceptionCfg() AdminConfig {
	return AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		MasterKey:  []byte("0123456789abcdef0123456789abcdef"),
	}
}

func postGrant(t *testing.T, cfg AdminConfig, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := NewAdminExceptionGrantHandler(cfg)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/exceptions/grant", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	h.ServeHTTP(rr, req)
	return rr
}

func TestExceptionGrantHappyPath(t *testing.T) {
	rr := postGrant(t, exceptionCfg(), "secret",
		`{"agent_id":"agent-finance-1","tools":["transfer_funds"],"ttl_seconds":3600,"exception_ref":"EXC0012345","approved_by":"risk.owner@acme"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["token"] == "" || resp["token"] == nil {
		t.Error("expected a minted token")
	}
	if resp["exception_ref"] != "EXC0012345" || resp["agent_id"] != "agent-finance-1" {
		t.Errorf("response missing correlation fields: %+v", resp)
	}
	if resp["expires_at"] == "" || resp["expires_at"] == nil {
		t.Error("expected an expiry")
	}
}

func TestExceptionGrantValidation(t *testing.T) {
	cfg := exceptionCfg()
	cases := map[string]string{
		"no agent":         `{"tools":["t"],"ttl_seconds":60,"exception_ref":"E1"}`,
		"no exception_ref": `{"agent_id":"a","tools":["t"],"ttl_seconds":60}`,
		"no ttl":           `{"agent_id":"a","tools":["t"],"exception_ref":"E1"}`,
		"no tools":         `{"agent_id":"a","ttl_seconds":60,"exception_ref":"E1"}`,
	}
	for name, body := range cases {
		rr := postGrant(t, cfg, "secret", body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, rr.Code)
		}
	}
}

func TestExceptionGrantTTLCap(t *testing.T) {
	cfg := exceptionCfg()
	cfg.ExceptionMaxTTL = time.Hour
	// Request 2h against a 1h cap → rejected.
	rr := postGrant(t, cfg, "secret",
		`{"agent_id":"a","tools":["t"],"ttl_seconds":7200,"exception_ref":"E1"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for over-cap ttl, got %d", rr.Code)
	}
	// 30m is within the cap → accepted.
	rr = postGrant(t, cfg, "secret",
		`{"agent_id":"a","tools":["t"],"ttl_seconds":1800,"exception_ref":"E1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 for in-cap ttl, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestExceptionGrantAuthAndMasterKey(t *testing.T) {
	// Missing bearer → 401.
	if rr := postGrant(t, exceptionCfg(), "",
		`{"agent_id":"a","tools":["t"],"ttl_seconds":60,"exception_ref":"E1"}`); rr.Code != http.StatusUnauthorized {
		t.Errorf("no auth: want 401, got %d", rr.Code)
	}
	// No master key → 503.
	cfg := exceptionCfg()
	cfg.MasterKey = nil
	if rr := postGrant(t, cfg, "secret",
		`{"agent_id":"a","tools":["t"],"ttl_seconds":60,"exception_ref":"E1"}`); rr.Code != http.StatusServiceUnavailable {
		t.Errorf("no master key: want 503, got %d", rr.Code)
	}
}
