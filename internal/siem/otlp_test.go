package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

func TestOTLPLogsURL(t *testing.T) {
	cases := map[string]string{
		"https://c.example:4318":           "https://c.example:4318/v1/logs",
		"https://c.example:4318/":          "https://c.example:4318/v1/logs",
		"https://c.example:4318/v1/logs":   "https://c.example:4318/v1/logs",
		"https://c.example:4318/v1/logs/":  "https://c.example:4318/v1/logs",
		"  https://c.example:4318/v1/logs": "https://c.example:4318/v1/logs",
	}
	for in, want := range cases {
		if got := otlpLogsURL(in); got != want {
			t.Errorf("otlpLogsURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewOTLPEmitterRequiresEndpoint(t *testing.T) {
	if _, err := NewOTLPEmitter(OTLPConfig{}); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestOTLPEmitterExportsLogRecord(t *testing.T) {
	var body atomic.Value
	body.Store([]byte(nil))
	var (
		hits    atomic.Int32
		gotCT   atomic.Value
		gotAuth atomic.Value
		gotPath atomic.Value
	)
	gotCT.Store("")
	gotAuth.Store("")
	gotPath.Store("")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		body.Store(b)
		gotCT.Store(r.Header.Get("Content-Type"))
		gotAuth.Store(r.Header.Get("api-key"))
		gotPath.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	em, err := NewOTLPEmitter(OTLPConfig{
		Endpoint:    srv.URL,
		ServiceName: "intentgate-test",
		Namespace:   "acme",
		Headers:     map[string]string{"api-key": "secret"},
		Logger:      quietLogger(),
	})
	if err != nil {
		t.Fatalf("NewOTLPEmitter: %v", err)
	}

	em.Emit(context.Background(), audit.Event{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Decision:  audit.DecisionBlock,
		Tool:      "db_delete",
		AgentID:   "agent-1",
		Tenant:    "acme",
		EventID:   "evt-123",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := em.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if hits.Load() == 0 {
		t.Fatal("expected at least one POST")
	}
	if p := gotPath.Load().(string); p != "/v1/logs" {
		t.Errorf("path = %q, want /v1/logs", p)
	}
	if ct := gotCT.Load().(string); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if a := gotAuth.Load().(string); a != "secret" {
		t.Errorf("api-key header = %q, want secret", a)
	}

	var payload otlpExportLogs
	raw := body.Load().([]byte)
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal body: %v (body=%s)", err, raw)
	}
	if len(payload.ResourceLogs) != 1 || len(payload.ResourceLogs[0].ScopeLogs) != 1 {
		t.Fatalf("unexpected structure: %+v", payload)
	}
	// service.name resource attribute present.
	var sawService bool
	for _, kv := range payload.ResourceLogs[0].Resource.Attributes {
		if kv.Key == "service.name" && kv.Value.StringValue != nil && *kv.Value.StringValue == "intentgate-test" {
			sawService = true
		}
	}
	if !sawService {
		t.Error("service.name resource attribute missing")
	}

	recs := payload.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	rec := recs[0]
	if rec.SeverityText != "ERROR" {
		t.Errorf("severity = %q, want ERROR for a block", rec.SeverityText)
	}
	if rec.TimeUnixNano == "" {
		t.Error("timeUnixNano empty")
	}

	attrs := map[string]string{}
	for _, kv := range rec.Attributes {
		if kv.Value.StringValue != nil {
			attrs[kv.Key] = *kv.Value.StringValue
		}
	}
	if attrs["intentgate.decision"] != "block" {
		t.Errorf("decision attr = %q, want block", attrs["intentgate.decision"])
	}
	if attrs["intentgate.tool"] != "db_delete" {
		t.Errorf("tool attr = %q, want db_delete", attrs["intentgate.tool"])
	}
	if attrs["intentgate.event_id"] != "evt-123" {
		t.Errorf("event_id attr = %q, want evt-123", attrs["intentgate.event_id"])
	}
}
