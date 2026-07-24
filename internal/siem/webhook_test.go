package siem

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

func TestNewWebhookEmitterRequiresURL(t *testing.T) {
	if _, err := NewWebhookEmitter(WebhookConfig{}); err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestWebhookEmitterSignsAndPostsEvents(t *testing.T) {
	const secret = "s3cr3t"
	var body atomic.Value
	body.Store([]byte(nil))
	var sig atomic.Value
	sig.Store("")
	var hits atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		body.Store(b)
		sig.Store(r.Header.Get("X-IntentGate-Signature"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em, err := NewWebhookEmitter(WebhookConfig{
		URL:    srv.URL,
		Secret: secret,
		Logger: quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhookEmitter: %v", err)
	}

	em.Emit(context.Background(), audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:  audit.DecisionAllow,
		Tool:      "db_query",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if hits.Load() == 0 {
		t.Fatal("expected at least one POST")
	}

	raw := body.Load().([]byte)
	var payload webhookPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, raw)
	}
	if len(payload.Events) != 1 || payload.Events[0].Tool != "db_query" {
		t.Fatalf("unexpected events: %+v", payload.Events)
	}

	// Signature must be a valid HMAC-SHA256 of the exact body.
	got := sig.Load().(string)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(raw)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !strings.EqualFold(got, want) {
		t.Errorf("signature = %q, want %q", got, want)
	}
}
