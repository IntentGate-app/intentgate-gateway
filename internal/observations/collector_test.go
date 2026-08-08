package observations

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// The platform recomputes raw_payload_hash and deduplication_key and REJECTS the batch on
// mismatch, so the Go collector must reproduce the TS hashing byte-for-byte. These expected
// values were produced by the platform's own computeRawPayloadHash / computeDeduplicationKey
// (packages/discovery-contracts/src/hashing.ts) — if either drifts, this test fails loudly.
const (
	wantPayloadHash = "28d16c7abcc6a7b41d211c784707c904216fe1432414911361ffa7fe2f37f7d3"
	wantDedupKey    = "0b3884ed5607138a0349ba1ca852b666e607e9368c5c8ff4fa1c80339a9f93df"
)

func TestCanonicalHashMatchesPlatform(t *testing.T) {
	got, err := canonicalHashHex(map[string]string{"type": "tools/call"})
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != wantPayloadHash {
		t.Fatalf("raw_payload_hash mismatch with platform:\n got  %s\n want %s", got, wantPayloadHash)
	}
}

func TestDedupKeyMatchesPlatform(t *testing.T) {
	got := dedupKeyHex("lab-tenant", "mcp-pep", "EVT", wantPayloadHash)
	if got != wantDedupKey {
		t.Fatalf("deduplication_key mismatch with platform:\n got  %s\n want %s", got, wantDedupKey)
	}
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestUUIDV4Shape(t *testing.T) {
	u, err := uuidV4()
	if err != nil {
		t.Fatalf("uuid: %v", err)
	}
	if !uuidRe.MatchString(u) {
		t.Fatalf("observation_id is not a valid v4 UUID: %q", u)
	}
}

func TestEmitPostsValidObservation(t *testing.T) {
	var captured wireObservation
	var authHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Errorf("ingest payload not a single observation object: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"SUCCESS","ingested_count":1}`))
	}))
	defer srv.Close()

	c, err := New(Config{URL: srv.URL, Token: "svc-token", Tenant: "lab-tenant"})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Emit(context.Background(), "agent-live-01", "read_invoice", "tools/call"); err != nil {
		t.Fatalf("emit: %v", err)
	}

	if authHeader != "Bearer svc-token" {
		t.Errorf("missing/incorrect bearer: %q", authHeader)
	}
	if captured.TenantID != "lab-tenant" {
		t.Errorf("tenant_id = %q, want lab-tenant", captured.TenantID)
	}
	if captured.SourceType != "MCP_PROXY" {
		t.Errorf("source_type = %q, want MCP_PROXY", captured.SourceType)
	}
	if captured.CollectorID != DefaultCollectorID {
		t.Errorf("collector_id = %q, want %s", captured.CollectorID, DefaultCollectorID)
	}
	if captured.Identifiers.AgentID != "agent-live-01" || captured.Identifiers.ToolID != "read_invoice" {
		t.Errorf("identifiers = %+v", captured.Identifiers)
	}
	if captured.RawPayload["type"] != "tools/call" {
		t.Errorf("raw_payload.type = %q, want tools/call (must NOT collapse to ACCESS)", captured.RawPayload["type"])
	}
	// The hash + dedup must be internally consistent so the platform accepts the batch.
	wantHash, _ := canonicalHashHex(captured.RawPayload)
	if captured.RawPayloadHash != wantHash {
		t.Errorf("raw_payload_hash %q inconsistent with payload (want %q)", captured.RawPayloadHash, wantHash)
	}
	wantDedup := dedupKeyHex(captured.TenantID, captured.CollectorID, captured.SourceEventID, captured.RawPayloadHash)
	if captured.DeduplicationKey != wantDedup {
		t.Errorf("deduplication_key %q inconsistent (want %q)", captured.DeduplicationKey, wantDedup)
	}
	if !uuidRe.MatchString(captured.ObservationID) {
		t.Errorf("observation_id not a v4 uuid: %q", captured.ObservationID)
	}
	if captured.Metadata.CollectorVersion == "" {
		t.Errorf("metadata.collector_version must be set")
	}
}

func TestEmitReturnsErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c, _ := New(Config{URL: srv.URL, Tenant: "lab-tenant"})
	if err := c.Emit(context.Background(), "a", "t", "tools/call"); err == nil {
		t.Fatal("expected an error on HTTP 500 (for logging), got nil")
	}
}

func TestEmitRequiresAgentAndTool(t *testing.T) {
	c, _ := New(Config{URL: "http://unused", Tenant: "lab-tenant"})
	if err := c.Emit(context.Background(), "", "t", "tools/call"); err == nil {
		t.Error("expected error for empty agentRef")
	}
	if err := c.Emit(context.Background(), "a", "", "tools/call"); err == nil {
		t.Error("expected error for empty toolRef")
	}
}

func TestNewRequiresURLAndTenant(t *testing.T) {
	if _, err := New(Config{Tenant: "lab-tenant"}); err == nil {
		t.Error("expected error when URL is empty")
	}
	if _, err := New(Config{URL: "http://x"}); err == nil {
		t.Error("expected error when Tenant is empty")
	}
}
