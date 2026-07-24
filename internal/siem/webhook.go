package siem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// WebhookConfig configures the generic HTTPS webhook telemetry adapter.
//
// This is a Lightweight-tier adapter: it POSTs batched audit events as
// JSON to any HTTPS receiver the customer already runs (an internal
// collector, an automation endpoint, a serverless function). It is the
// "Direct HTTPS Webhooks" box in the telemetry architecture, and is
// distinct from the console-notification webhook (internal/webhook,
// INTENTGATE_WEBHOOK_URL), which fans findings out to Slack/Teams via
// console-pro. This one is a raw telemetry sink under the SIEM fan-out.
type WebhookConfig struct {
	// URL is the receiver endpoint. Required.
	URL string
	// Secret, when set, signs each request body with HMAC-SHA256 and
	// sends the hex digest in the "X-IntentGate-Signature: sha256=..."
	// header so the receiver can verify authenticity. Never logged.
	Secret string
	// HTTPClient is injected in tests; nil falls back to a default
	// client with a 30-second total timeout.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// WebhookEmitter ships batched audit events to an HTTPS endpoint. Each
// flush is one POST of a JSON object {"events": [...]}.
type WebhookEmitter struct {
	cfg  WebhookConfig
	be   *batchEmitter
	name string
}

// NewWebhookEmitter validates config, builds the emitter, and starts its
// worker.
func NewWebhookEmitter(cfg WebhookConfig) (*WebhookEmitter, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("siem/webhook: URL is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	we := &WebhookEmitter{cfg: cfg, name: "webhook"}
	we.be = newBatchEmitter(batchConfig{
		Name:   we.name,
		Flush:  httpFlusher(cfg.HTTPClient, we.buildRequest),
		Logger: cfg.Logger,
	})
	return we, nil
}

// Emit forwards the event to the batched worker.
func (w *WebhookEmitter) Emit(ctx context.Context, ev audit.Event) { w.be.Emit(ctx, ev) }

// Stop drains the worker.
func (w *WebhookEmitter) Stop(ctx context.Context) error { return w.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The URL is
// exposed; the signing secret never is.
func (w *WebhookEmitter) Status() Status {
	return w.be.snapshot(w.name, w.cfg.URL, true)
}

type webhookPayload struct {
	Events []audit.Event `json:"events"`
}

func (w *WebhookEmitter) buildRequest(events []audit.Event) (*http.Request, error) {
	body, err := json.Marshal(webhookPayload{Events: events})
	if err != nil {
		return nil, fmt.Errorf("siem/webhook: marshal: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, w.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("siem/webhook: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.cfg.Secret))
		mac.Write(body)
		req.Header.Set("X-IntentGate-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	return req, nil
}
