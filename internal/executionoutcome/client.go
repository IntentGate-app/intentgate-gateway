// Package executionoutcome is the data-plane PEP's client for recording what happened
// AFTER an authorization decision — the EXO- execution-outcome evidence linked to a DEC-.
//
// It is deliberately separate from the authorization decision: the PEP posts an outcome
// only when a DEC- already exists (ALLOW forwarded, or a governed DENY that blocked before
// the toolserver). A fail-closed (control plane unreachable, so NO DEC- was written) emits
// NOTHING here — the outcome must never manufacture a decision relationship that does not
// exist; that event belongs in operational/audit telemetry instead.
//
// Emission is best-effort and OFF the decision path: a post failure never alters the
// authorization or execution result. The platform re-sanitizes `detail` on ingest as the
// final trust boundary, so this client only ever sends already-safe fields.
package executionoutcome

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout bounds a single best-effort emit.
const DefaultTimeout = 3 * time.Second

// Execution status values, matching the platform ExecutionStatus enum. ATTEMPTED is not
// used by the PEP today (it records terminal outcomes); it exists for future async flows.
const (
	StatusExecuted = "EXECUTED"
	StatusBlocked  = "BLOCKED"
	StatusFailed   = "FAILED"
)

// Config configures a Client. Tenant is derived by the platform from the token, so — unlike
// the observations collector — no tenant is sent in the body.
type Config struct {
	// URL is the platform ingest endpoint, e.g.
	// http://intentgate-gateway:4000/api/v1/discovery/execution-outcomes. Required.
	URL string
	// Token is the service-to-service bearer; the platform derives the tenant from it.
	Token string
	// Timeout bounds one emit; zero selects DefaultTimeout.
	Timeout time.Duration
	// HTTPClient is optional; one is built from Timeout when nil (tests inject one).
	HTTPClient *http.Client
}

// Client posts execution outcomes to the control plane. Safe for concurrent use.
type Client struct {
	url   string
	token string
	http  *http.Client
}

// New constructs a Client. Errors when URL is empty.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("executionoutcome: URL is required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		to := cfg.Timeout
		if to <= 0 {
			to = DefaultTimeout
		}
		hc = &http.Client{Timeout: to}
	}
	return &Client{url: cfg.URL, token: cfg.Token, http: hc}, nil
}

// Detail is the bounded, PII-safe execution detail: identifiers/codes only — never prompts,
// arguments, results, or secrets.
type Detail struct {
	Tool      string `json:"tool,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// Outcome is what the PEP records after acting on a decision.
type Outcome struct {
	DecisionID     string
	Status         string
	UpstreamStatus *int
	ResultHash     string
	TraceID        string
	Detail         Detail
}

// HashResult returns the SHA-256 hex of a tool response body — evidence of the result
// without ever storing the payload itself.
func HashResult(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Emit posts one execution outcome. Best-effort: a non-nil error is for logging only and
// MUST NOT influence the authorization or execution result. Callers should skip emission
// entirely when there is no decision_id (no DEC- to link to).
func (c *Client) Emit(ctx context.Context, o Outcome) error {
	if o.DecisionID == "" {
		return errors.New("executionoutcome: decision_id is required")
	}
	payload := map[string]any{
		"decision_id": o.DecisionID,
		"status":      o.Status,
		"detail":      o.Detail,
	}
	if o.UpstreamStatus != nil {
		payload["upstream_status"] = *o.UpstreamStatus
	}
	if o.ResultHash != "" {
		payload["result_hash"] = o.ResultHash
	}
	if o.TraceID != "" {
		payload["trace_id"] = o.TraceID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("executionoutcome: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("executionoutcome: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("executionoutcome: request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("executionoutcome: control plane HTTP %d", resp.StatusCode)
	}
	return nil
}
