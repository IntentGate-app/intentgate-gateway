// Package intentauthz is the data-plane PEP's client to the IntentGate control
// plane's MCP authorization decision (the "Layer 1" endpoint,
// POST /api/v1/discovery/authorize/mcp).
//
// It asks a single question — may THIS agent invoke THIS tool right now? — and
// returns the governed decision derived from the BA-/IG- chain. It never decides
// locally: an unreachable, slow, or malformed control plane surfaces as a non-nil
// error, and the caller MUST treat that as fail-closed (block), never as allow.
package intentauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout bounds a single authorize call. Short by design: the decision is
// on the hot path of every governed tool call, and a slow control plane must fail
// closed quickly rather than stall the agent.
const DefaultTimeout = 3 * time.Second

// Config configures a Client.
type Config struct {
	// URL is the control-plane MCP-authorize endpoint. Required.
	// e.g. http://intentgate-gateway:4000/api/v1/discovery/authorize/mcp
	URL string
	// Token is the service-to-service bearer presented to the control plane.
	Token string
	// Timeout bounds one call; zero selects DefaultTimeout.
	Timeout time.Duration
	// HTTPClient is optional; one is built from Timeout when nil (tests inject one).
	HTTPClient *http.Client
}

// Client is a configured connection to the control-plane MCP-authorize endpoint.
// Safe for concurrent use.
type Client struct {
	url   string
	token string
	http  *http.Client
}

// New constructs a Client. Errors when URL is empty.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("intentauthz: URL is required")
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

// Request is the raw MCP call to authorize. The control plane resolves agent_ref
// and tool_ref to canonical EUIDs (via entity_source_mappings, source_type mcp)
// and normalizes the method; the data plane never has to know the identity model.
type Request struct {
	AgentRef string         `json:"agent_ref"`
	ToolRef  string         `json:"tool_ref"`
	Method   string         `json:"method"`
	Context  map[string]any `json:"context,omitempty"`
}

// Record is the immutable decision evidence the control plane persisted (DEC-).
type Record struct {
	DecisionID        string  `json:"decision_id"`
	ReasonCode        string  `json:"reason_code"`
	GrantID           *string `json:"grant_id"`
	SourceAuthorityID *string `json:"source_authority_id"`
}

// Decision is the control plane's answer.
type Decision struct {
	Decision string `json:"decision"` // ALLOW | DENY
	Record   Record `json:"record"`
}

// Allowed reports whether execution is permitted. Anything other than an explicit
// ALLOW is not permitted.
func (d *Decision) Allowed() bool { return d != nil && d.Decision == "ALLOW" }

// Authorize calls the control-plane PDP. A non-nil error means the decision could
// NOT be obtained (network, timeout, non-2xx, unparseable body, unknown verdict).
// The caller MUST treat a non-nil error as fail-closed — block, never forward.
func (c *Client) Authorize(ctx context.Context, in Request) (*Decision, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("intentauthz: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("intentauthz: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("intentauthz: request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("intentauthz: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("intentauthz: control plane HTTP %d", resp.StatusCode)
	}

	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("intentauthz: decode: %w", err)
	}
	if d.Decision != "ALLOW" && d.Decision != "DENY" {
		return nil, fmt.Errorf("intentauthz: unexpected decision %q", d.Decision)
	}
	return &d, nil
}
