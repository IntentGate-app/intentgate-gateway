package handlers

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/payloads"
)

// delivered stands in for the post-filter envelope handed to the agent. The
// raw upstream bytes are deliberately different, which is the normal case once
// the PII filter or output-schema guard has touched the response.
type delivered struct {
	Result string `json:"result"`
}

func captureHandler(store payloads.Store, pol payloads.Policy) *mcpHandler {
	return &mcpHandler{cfg: MCPHandlerConfig{
		Logger:        slog.Default(),
		Payloads:      store,
		PayloadPolicy: pol,
	}}
}

func applied(opt auditEmitOption) audit.Event {
	var e audit.Event
	opt(&e)
	return e
}

// Default posture: nothing is retained and the event says nothing about a
// result. Capture must be invisible until someone asks for it.
func TestCaptureDisabledStoresNothing(t *testing.T) {
	store := payloads.NewMemory()
	h := captureHandler(store, payloads.Policy{})

	opt := h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "agent-procure-1"},
		"read_invoice", []byte(`{"raw":true}`), delivered{Result: "ok"})

	e := applied(opt)
	if e.ResultSHA256 != "" || e.ResultBytes != 0 || e.ResultStored {
		t.Fatalf("disabled capture annotated the event: %+v", e)
	}
	if _, err := store.Get(context.Background(), "", "e1"); !errors.Is(err, payloads.ErrNotFound) {
		t.Fatal("disabled capture wrote a payload")
	}
}

// The hash must be of the RAW upstream bytes, not of what was stored. That is
// what makes the record an anchor to what the upstream actually returned
// rather than a restatement of what we chose to keep.
func TestCaptureHashesRawNotStored(t *testing.T) {
	store := payloads.NewMemory()
	h := captureHandler(store, payloads.Policy{Enabled: true, Tools: []string{"*"}})

	raw := []byte(`{"jsonrpc":"2.0","result":{"secret":"visible"}}`)
	opt := h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "agent-procure-1"},
		"read_invoice", raw, delivered{Result: "redacted"})

	e := applied(opt)
	if e.ResultSHA256 != payloads.HashRaw(raw) {
		t.Fatalf("hash is not of the raw upstream body")
	}
	if e.ResultBytes != len(raw) {
		t.Fatalf("ResultBytes = %d, want %d", e.ResultBytes, len(raw))
	}
	if !e.ResultStored {
		t.Fatal("ResultStored false after a successful store")
	}

	rec, err := store.Get(context.Background(), "", "e1")
	if err != nil {
		t.Fatal(err)
	}
	// What is stored is the delivered form, never the raw one.
	if string(rec.Body) == string(raw) {
		t.Fatal("stored body is the raw upstream response, not the redacted one")
	}
	if !rec.Redacted {
		t.Fatal("record does not report that the body differs from the raw form")
	}
	if rec.RawSHA256 != payloads.HashRaw(raw) {
		t.Fatal("record hash does not match the raw body")
	}
}

// A tool outside the configured set is not captured even while capture is on
// for others.
func TestCaptureRespectsToolSelection(t *testing.T) {
	store := payloads.NewMemory()
	h := captureHandler(store, payloads.Policy{Enabled: true, Tools: []string{"agent:*"}})

	opt := h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "a"},
		"transfer_funds", []byte(`{"x":1}`), delivered{Result: "ok"})

	if e := applied(opt); e.ResultSHA256 != "" {
		t.Fatal("captured a tool outside the selection")
	}
}

// An agent-to-agent hand-off is captured by the agent: pattern, which is the
// posture that makes inter-agent traffic visible without retaining tool
// results.
func TestCaptureCoversAgentToAgent(t *testing.T) {
	store := payloads.NewMemory()
	h := captureHandler(store, payloads.Policy{Enabled: true, Tools: []string{"agent:*"}})

	opt := h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "agent-procure-1"},
		"agent:agent-finance-1", []byte(`{"ack":true}`), delivered{Result: "ack"})

	if e := applied(opt); !e.ResultStored {
		t.Fatal("agent-to-agent response was not captured")
	}
	rec, err := store.Get(context.Background(), "", "e1")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Tool != "agent:agent-finance-1" {
		t.Fatalf("tool = %q", rec.Tool)
	}
}

// A capture failure must never surface to the agent, and must not claim a
// payload exists. The hash still lands, because it was computed before the
// store was involved and is useful on its own.
func TestCaptureSurvivesStoreFailure(t *testing.T) {
	h := captureHandler(nil, payloads.Policy{Enabled: true, Tools: []string{"*"}})
	h.cfg.Payloads = nil // no store wired at all

	raw := []byte(`{"x":1}`)
	e := applied(h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "a"}, "read_invoice", raw, delivered{Result: "ok"}))

	if e.ResultSHA256 != payloads.HashRaw(raw) {
		t.Fatal("hash missing when no store is configured")
	}
	if e.ResultStored {
		t.Fatal("claimed a payload was stored with no store configured")
	}
}

// An empty upstream body is not a payload worth a row.
func TestCaptureIgnoresEmptyUpstream(t *testing.T) {
	store := payloads.NewMemory()
	h := captureHandler(store, payloads.Policy{Enabled: true, Tools: []string{"*"}})

	if e := applied(h.capturePayload(context.Background(), "e1",
		capabilityCheckResult{agentID: "a"}, "read_invoice", nil, delivered{})); e.ResultSHA256 != "" {
		t.Fatal("annotated an event for an empty response")
	}
}
