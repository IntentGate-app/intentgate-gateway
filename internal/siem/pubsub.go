package siem

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// PubSubConfig configures the native Google Cloud Pub/Sub telemetry adapter.
//
// Pub/Sub is the first-class streaming target on GCP. This adapter publishes
// over the Pub/Sub REST API (publish method) rather than pulling in the heavy
// gRPC client library, so it stays dependency-light and matches the other HTTP
// sinks. Like every adapter it is async downstream of the Telemetry Adapter
// Interface: a slow or unavailable topic can never add latency to the inline
// decision, because the shared batch worker drops on a full buffer.
//
// Authentication is a Bearer OAuth access token. In order of preference:
//   - StaticToken, when set (useful for tests / an emulator / a short-lived
//     token injected by a sidecar).
//   - Otherwise the GCP metadata server (workload identity): the adapter
//     fetches an access token for the default service account and refreshes it
//     shortly before expiry. This is the normal production path on GKE / GCE.
type PubSubConfig struct {
	// ProjectID and Topic identify the destination topic. Both required.
	ProjectID string
	Topic     string
	// StaticToken, when set, is used verbatim as the Bearer token. Empty means
	// fetch from the metadata server.
	StaticToken string
	// Endpoint overrides the API base (default https://pubsub.googleapis.com),
	// for the Pub/Sub emulator or a private endpoint.
	Endpoint string
	// HTTPClient is injected in tests; nil uses a 30s-timeout client.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// PubSubEmitter publishes audit events to a Pub/Sub topic, one message per
// event, keyed via a "tenant" attribute so a multi-cloud SOC can filter by
// trust domain. It reuses the shared batch worker for the non-blocking,
// drops-not-blocks contract every adapter shares.
type PubSubEmitter struct {
	cfg   PubSubConfig
	be    *batchEmitter
	url   string
	name  string
	label string

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewPubSubEmitter validates config and starts the worker. The first publish
// (not startup) triggers the first token fetch, keeping pod startup fast.
func NewPubSubEmitter(cfg PubSubConfig) (*PubSubEmitter, error) {
	if strings.TrimSpace(cfg.ProjectID) == "" {
		return nil, errors.New("siem/pubsub: ProjectID is required")
	}
	if strings.TrimSpace(cfg.Topic) == "" {
		return nil, errors.New("siem/pubsub: Topic is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://pubsub.googleapis.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	pe := &PubSubEmitter{
		cfg:   cfg,
		url:   fmt.Sprintf("%s/v1/projects/%s/topics/%s:publish", strings.TrimRight(cfg.Endpoint, "/"), cfg.ProjectID, cfg.Topic),
		name:  "pubsub",
		label: fmt.Sprintf("pubsub://%s/%s", cfg.ProjectID, cfg.Topic),
	}
	pe.be = newBatchEmitter(batchConfig{
		Name:   pe.name,
		Flush:  httpFlusher(cfg.HTTPClient, pe.buildRequest),
		Logger: cfg.Logger,
	})
	return pe, nil
}

// Emit forwards the event to the batched worker.
func (p *PubSubEmitter) Emit(ctx context.Context, ev audit.Event) { p.be.Emit(ctx, ev) }

// Stop drains the worker.
func (p *PubSubEmitter) Stop(ctx context.Context) error { return p.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The topic path is
// exposed; the token never is.
func (p *PubSubEmitter) Status() Status {
	return p.be.snapshot(p.name, p.label, true)
}

// pubsubMessage is the REST wire shape: data is base64 of the event JSON, and
// attributes carry the small string metadata Pub/Sub subscribers filter on.
type pubsubMessage struct {
	Data       string            `json:"data"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type pubsubPublishRequest struct {
	Messages []pubsubMessage `json:"messages"`
}

func (p *PubSubEmitter) buildRequest(events []audit.Event) (*http.Request, error) {
	msgs := make([]pubsubMessage, 0, len(events))
	for i := range events {
		b, err := json.Marshal(&events[i])
		if err != nil {
			continue
		}
		attrs := map[string]string{}
		if events[i].Tenant != "" {
			attrs["tenant"] = events[i].Tenant
		}
		if events[i].Decision != "" {
			attrs["decision"] = string(events[i].Decision)
		}
		msgs = append(msgs, pubsubMessage{
			Data:       base64.StdEncoding.EncodeToString(b),
			Attributes: attrs,
		})
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(pubsubPublishRequest{Messages: msgs}); err != nil {
		return nil, fmt.Errorf("siem/pubsub: encode: %w", err)
	}

	token, err := p.accessToken()
	if err != nil {
		return nil, fmt.Errorf("siem/pubsub: token: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, p.url, &buf)
	if err != nil {
		return nil, fmt.Errorf("siem/pubsub: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// accessToken returns a valid Bearer token: the static one if configured, or a
// metadata-server token cached until shortly before its expiry. Concurrency-
// safe; only one fetch happens across parallel flushes.
func (p *PubSubEmitter) accessToken() (string, error) {
	if p.cfg.StaticToken != "" {
		return p.cfg.StaticToken, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.token != "" && time.Now().Before(p.tokenExp) {
		return p.token, nil
	}
	tok, ttl, err := p.fetchMetadataToken()
	if err != nil {
		return "", err
	}
	p.token = tok
	// Refresh a minute before the real expiry so a token is never used at the
	// edge of its lifetime.
	p.tokenExp = time.Now().Add(ttl - time.Minute)
	return tok, nil
}

// fetchMetadataToken pulls a service-account access token from the GCP metadata
// server (workload identity). Only reachable inside GCP; elsewhere, set
// StaticToken instead.
func (p *PubSubEmitter) fetchMetadataToken() (string, time.Duration, error) {
	const metadataURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	req, err := http.NewRequest(http.MethodGet, metadataURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("metadata token status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", 0, err
	}
	if body.AccessToken == "" {
		return "", 0, errors.New("metadata token empty")
	}
	ttl := time.Duration(body.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 55 * time.Minute
	}
	return body.AccessToken, ttl, nil
}
