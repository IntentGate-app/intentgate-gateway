// Package observations is the data-plane PEP's collector for real MCP execution
// telemetry. Every governed tools/call the PEP sees is captured AT THE INTERCEPTION
// POINT — where the actor, tool, method and timestamp are ground truth — and shipped
// to the control-plane Observation Ingestion endpoint (POST /api/v1/discovery/observations).
//
// The platform owns everything downstream: normalize → correlate (Enterprise Twin) →
// Authority Mining. The PEP only captures execution truth; it never reconstructs an
// observation from later state, and it never synthesizes discovery logic locally.
//
// Two invariants:
//   - Capture is INDEPENDENT of the authorization result. An attempted/denied call is
//     just as real as an allowed one, and Authority Mining must see both — otherwise it
//     only ever learns from already-permitted behavior and can never propose the first
//     authority for a brand-new agent→tool edge.
//   - Capture is BEST-EFFORT and off the decision path. Emit never blocks, never changes,
//     and never fails, the enforcement decision. A collector error is logged and dropped.
package observations

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// DefaultCollectorID identifies this collector in every emitted observation.
	DefaultCollectorID = "mcp-pep"
	// DefaultCollectorVersion is stamped into observation metadata.
	DefaultCollectorVersion = "0.1.0"
	// DefaultEnvironment matches the platform Observation schema's metadata default.
	DefaultEnvironment = "production"
	// DefaultTimeout bounds a single emit. Short: capture must never slow enforcement.
	DefaultTimeout = 3 * time.Second
	// SourceType is the canonical collector enum for MCP proxy telemetry. The platform
	// correlator + miner normalize MCP_PROXY onto the internal `mcp` namespace.
	SourceType = "MCP_PROXY"
	// eventTypeToolsCall is the raw action retained in raw_payload.type, which the miner
	// reads as source_action and normalizes to tool.invoke — never collapsed to ACCESS.
	eventTypeToolsCall = "tools/call"
)

// Config configures a Collector.
type Config struct {
	// URL is the control-plane ingest endpoint. Required.
	// e.g. http://intentgate-gateway:4000/api/v1/discovery/observations
	URL string
	// Token is the service-to-service bearer presented to the control plane. The
	// platform derives tenant from this token; Tenant below must match it.
	Token string
	// Tenant is the tenant every observation is stamped with. Required, and it MUST
	// equal the tenant the Token authenticates as, or the platform rejects the batch
	// with a tenant-context mismatch.
	Tenant string
	// CollectorID overrides DefaultCollectorID.
	CollectorID string
	// CollectorVersion overrides DefaultCollectorVersion.
	CollectorVersion string
	// Environment overrides DefaultEnvironment.
	Environment string
	// Timeout bounds one emit; zero selects DefaultTimeout.
	Timeout time.Duration
	// HTTPClient is optional; one is built from Timeout when nil (tests inject one).
	HTTPClient *http.Client
}

// Collector ships MCP execution observations to the control plane. Safe for concurrent use.
type Collector struct {
	url              string
	token            string
	tenant           string
	collectorID      string
	collectorVersion string
	environment      string
	http             *http.Client
}

// New constructs a Collector. Errors when URL or Tenant is empty.
func New(cfg Config) (*Collector, error) {
	if cfg.URL == "" {
		return nil, errors.New("observations: URL is required")
	}
	if cfg.Tenant == "" {
		return nil, errors.New("observations: Tenant is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		to := cfg.Timeout
		if to <= 0 {
			to = DefaultTimeout
		}
		hc = &http.Client{Timeout: to}
	}
	return &Collector{
		url:              cfg.URL,
		token:            cfg.Token,
		tenant:           cfg.Tenant,
		collectorID:      orDefault(cfg.CollectorID, DefaultCollectorID),
		collectorVersion: orDefault(cfg.CollectorVersion, DefaultCollectorVersion),
		environment:      orDefault(cfg.Environment, DefaultEnvironment),
		http:             hc,
	}, nil
}

// wire shapes match the platform ObservationSchema exactly.
type wireIdentifiers struct {
	AgentID string `json:"agent_id"`
	ToolID  string `json:"tool_id"`
}

type wireMetadata struct {
	Environment      string `json:"environment"`
	CollectorVersion string `json:"collector_version"`
}

type wireObservation struct {
	ObservationID    string            `json:"observation_id"`
	TenantID         string            `json:"tenant_id"`
	CollectorID      string            `json:"collector_id"`
	SourceType       string            `json:"source_type"`
	SourceEventID    string            `json:"source_event_id"`
	Identifiers      wireIdentifiers   `json:"identifiers"`
	ObservedAt       string            `json:"observed_at"`
	IngestedAt       string            `json:"ingested_at"`
	RawPayload       map[string]string `json:"raw_payload"`
	RawPayloadHash   string            `json:"raw_payload_hash"`
	DeduplicationKey string            `json:"deduplication_key"`
	Metadata         wireMetadata      `json:"metadata"`
}

// Emit captures one MCP tools/call as an observation and ships it to the control
// plane. Best-effort: a non-nil error is for logging only and MUST NOT influence the
// enforcement decision. Call it for every tools/call regardless of ALLOW/DENY.
func (c *Collector) Emit(ctx context.Context, agentRef, toolRef, method string) error {
	if agentRef == "" || toolRef == "" {
		return errors.New("observations: agentRef and toolRef are required")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// raw_payload is deliberately minimal and PII-free: the event type only. Argument
	// values (account numbers, amounts) are intentionally NOT captured here — the
	// identifiers (agent, tool) plus the action are the discovery signal, and keeping
	// values out avoids writing sensitive parameters into the observation store.
	rawPayload := map[string]string{"type": eventType(method)}
	payloadHash, err := canonicalHashHex(rawPayload)
	if err != nil {
		return fmt.Errorf("observations: hash payload: %w", err)
	}
	obsID, err := uuidV4()
	if err != nil {
		return fmt.Errorf("observations: gen observation id: %w", err)
	}
	// A fresh event id per call makes each real call a distinct observation (the dedup
	// key derives from it), so repeated identical calls all accumulate as evidence.
	eventID, err := uuidV4()
	if err != nil {
		return fmt.Errorf("observations: gen event id: %w", err)
	}

	obs := wireObservation{
		ObservationID:    obsID,
		TenantID:         c.tenant,
		CollectorID:      c.collectorID,
		SourceType:       SourceType,
		SourceEventID:    eventID,
		Identifiers:      wireIdentifiers{AgentID: agentRef, ToolID: toolRef},
		ObservedAt:       now,
		IngestedAt:       now, // platform overwrites on commit; required by the input schema.
		RawPayload:       rawPayload,
		RawPayloadHash:   payloadHash,
		DeduplicationKey: dedupKeyHex(c.tenant, c.collectorID, eventID, payloadHash),
		Metadata:         wireMetadata{Environment: c.environment, CollectorVersion: c.collectorVersion},
	}

	body, err := json.Marshal(obs)
	if err != nil {
		return fmt.Errorf("observations: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("observations: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("observations: request: %w", err)
	}
	defer resp.Body.Close()
	// Drain a little so the connection can be reused; ignore the body content.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("observations: control plane HTTP %d", resp.StatusCode)
	}
	return nil
}

// eventType maps a JSON-RPC method to the retained raw event type. Only tools/call is
// captured today; the mapping is explicit so a future consequential method is a
// deliberate addition rather than a silent passthrough.
func eventType(method string) string {
	if method == eventTypeToolsCall {
		return eventTypeToolsCall
	}
	return method
}

// canonicalHashHex reproduces the platform's computeRawPayloadHash: SHA-256 over the
// key-sorted, compact JSON of the payload. Go's json sorts map keys and emits compact
// output; disabling HTML escaping matches JSON.stringify byte-for-byte.
func canonicalHashHex(payload map[string]string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return "", err
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n") // Encode appends a newline.
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// dedupKeyHex reproduces the platform's computeDeduplicationKey: SHA-256 over
// tenant|collector|sourceEventId|payloadHash.
func dedupKeyHex(tenant, collector, sourceEventID, payloadHash string) string {
	seed := tenant + "|" + collector + "|" + sourceEventID + "|" + payloadHash
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// uuidV4 returns a random RFC-4122 v4 UUID (the observation_id must be a valid UUID).
func uuidV4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
