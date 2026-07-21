package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/payloads"
)

// recordingEmitter captures emitted audit events so a test can assert that
// reading customer data left a trail.
type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) {
	r.events = append(r.events, e)
}

func payloadTestCfg(t *testing.T) (AdminConfig, *payloads.MemoryStore, *recordingEmitter) {
	t.Helper()
	store := payloads.NewMemory()
	_ = store.Put(context.Background(), payloads.Record{
		EventID:    "evt-1",
		Tenant:     "acme",
		AgentID:    "agent-procure-1",
		Tool:       "agent:agent-finance-1",
		RawSHA256:  payloads.HashRaw([]byte(`{"raw":"secret"}`)),
		RawBytes:   16,
		Body:       []byte(`{"result":"redacted"}`),
		Redacted:   true,
		CapturedAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(time.Hour),
	})
	em := &recordingEmitter{}
	return AdminConfig{
		Logger:       slog.Default(),
		AdminToken:   "super-token",
		TenantAdmins: map[string]string{"acme": "acme-token", "other": "other-token"},
		Payloads:     store,
		Audit:        em,
	}, store, em
}

func getPayload(cfg AdminConfig, token, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	NewAdminPayloadHandler(cfg).ServeHTTP(w, r)
	return w
}

func TestPayloadReadRequiresAuth(t *testing.T) {
	cfg, _, _ := payloadTestCfg(t)
	if got := getPayload(cfg, "", "/v1/admin/payloads/evt-1").Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", got)
	}
	if got := getPayload(cfg, "wrong", "/v1/admin/payloads/evt-1").Code; got != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d, want 401", got)
	}
}

// The whole point of the design: reading retained customer data leaves a
// record. If this test ever fails, the store has become a shadow copy nobody
// is accountable for.
func TestPayloadReadIsItselfAudited(t *testing.T) {
	cfg, _, em := payloadTestCfg(t)
	if got := getPayload(cfg, "acme-token", "/v1/admin/payloads/evt-1").Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if len(em.events) != 1 {
		t.Fatalf("emitted %d audit events, want exactly 1", len(em.events))
	}
	e := em.events[0]
	if e.EventName != "payload_read" {
		t.Fatalf("event name = %q", e.EventName)
	}
	if e.Tenant != "acme" || e.CapabilityTokenID != "evt-1" {
		t.Fatalf("event does not identify what was read: %+v", e)
	}
}

// A failed read is still an access attempt worth recording.
func TestPayloadMissIsAudited(t *testing.T) {
	cfg, _, em := payloadTestCfg(t)
	if got := getPayload(cfg, "acme-token", "/v1/admin/payloads/nope").Code; got != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", got)
	}
	if len(em.events) != 1 {
		t.Fatalf("a miss emitted %d events, want 1", len(em.events))
	}
	if em.events[0].ResultStored {
		t.Fatal("a miss was recorded as though a payload was returned")
	}
}

// A tenant admin must not be able to read another tenant's payload, either by
// naming it or by omitting the parameter and hoping.
func TestPayloadReadIsTenantScoped(t *testing.T) {
	cfg, _, _ := payloadTestCfg(t)

	// Explicitly asking for another tenant is refused outright.
	if got := getPayload(cfg, "acme-token", "/v1/admin/payloads/evt-1?tenant=other").Code; got != http.StatusForbidden {
		t.Fatalf("cross-tenant request status = %d, want 403", got)
	}
	// And another tenant's admin simply cannot see acme's row.
	if got := getPayload(cfg, "other-token", "/v1/admin/payloads/evt-1").Code; got != http.StatusNotFound {
		t.Fatalf("other tenant read status = %d, want 404", got)
	}
}

// A superadmin has no cross-tenant sweep: they must name the tenant. Allowing
// an unscoped read is precisely the shape of incident this design prevents.
func TestSuperadminMustNameTheTenant(t *testing.T) {
	cfg, _, _ := payloadTestCfg(t)
	if got := getPayload(cfg, "super-token", "/v1/admin/payloads/evt-1").Code; got != http.StatusBadRequest {
		t.Fatalf("unscoped superadmin read status = %d, want 400", got)
	}
	if got := getPayload(cfg, "super-token", "/v1/admin/payloads/evt-1?tenant=acme").Code; got != http.StatusOK {
		t.Fatalf("scoped superadmin read status = %d, want 200", got)
	}
}

// The response must carry the redacted body and the hash of the raw one, and
// must never claim the raw response is what is stored.
func TestPayloadResponseShape(t *testing.T) {
	cfg, _, _ := payloadTestCfg(t)
	w := getPayload(cfg, "acme-token", "/v1/admin/payloads/evt-1")

	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["raw_sha256"] != payloads.HashRaw([]byte(`{"raw":"secret"}`)) {
		t.Fatalf("raw_sha256 missing or wrong: %v", got["raw_sha256"])
	}
	if got["redacted"] != true {
		t.Fatal("response does not report that the body is redacted")
	}
	body, _ := json.Marshal(got["body"])
	if string(body) != `{"result":"redacted"}` {
		t.Fatalf("body = %s", body)
	}
}

// With no store wired the route should say capture is off, not imply this one
// call had nothing worth keeping.
func TestPayloadReadWhenCaptureDisabled(t *testing.T) {
	cfg, _, _ := payloadTestCfg(t)
	cfg.Payloads = nil
	w := getPayload(cfg, "acme-token", "/v1/admin/payloads/evt-1")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if !contains(w.Body.String(), "not enabled") {
		t.Fatalf("body does not explain capture is off: %s", w.Body.String())
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (len(needle) == 0 || indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
