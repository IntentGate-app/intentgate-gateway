package riskregister

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ServiceNowConfig configures the ServiceNow IRM/GRC risk-register exporter.
//
// It writes to the ServiceNow Table API: risk indicators to an indicator
// table and threshold breaches to an issue table. The exact IRM schema
// varies by instance and scoped-app install, so both table names are
// overridable and the record bodies use u_ custom columns that a customer
// maps to their real indicator/issue definitions.
type ServiceNowConfig struct {
	// InstanceURL is the base instance, e.g. "https://acme.service-now.com".
	// Required. A trailing slash is tolerated.
	InstanceURL string
	// IndicatorTable receives per-window risk indicators. Defaults to
	// "sn_risk_indicator_result".
	IndicatorTable string
	// IssueTable receives threshold-breach issues. Defaults to
	// "sn_grc_issue".
	IssueTable string

	// Auth: basic (Username/Password) or OAuth2 client-credentials
	// (ClientID/ClientSecret). OAuth2 takes precedence when both are set.
	Username     string
	Password     string
	ClientID     string
	ClientSecret string

	// HTTPClient is injected in tests; nil falls back to a 30s-timeout client.
	HTTPClient *http.Client
	// Logger; nil falls back to slog.Default.
	Logger *slog.Logger
}

// ServiceNowExporter implements [Exporter] against ServiceNow IRM.
type ServiceNowExporter struct {
	cfg      ServiceNowConfig
	base     string
	indTable string
	issueTbl string
	client   *http.Client
	mu       sync.Mutex
	token    string
	tokenAt  time.Time
}

// NewServiceNowExporter validates config and returns the exporter.
func NewServiceNowExporter(cfg ServiceNowConfig) (*ServiceNowExporter, error) {
	if strings.TrimSpace(cfg.InstanceURL) == "" {
		return nil, errors.New("riskregister/servicenow: InstanceURL is required")
	}
	oauth := cfg.ClientID != "" && cfg.ClientSecret != ""
	basic := cfg.Username != "" && cfg.Password != ""
	if !oauth && !basic {
		return nil, errors.New("riskregister/servicenow: set Username/Password (basic) or ClientID/ClientSecret (oauth2)")
	}
	if cfg.IndicatorTable == "" {
		cfg.IndicatorTable = "sn_risk_indicator_result"
	}
	if cfg.IssueTable == "" {
		cfg.IssueTable = "sn_grc_issue"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &ServiceNowExporter{
		cfg:      cfg,
		base:     strings.TrimRight(strings.TrimSpace(cfg.InstanceURL), "/"),
		indTable: cfg.IndicatorTable,
		issueTbl: cfg.IssueTable,
		client:   cfg.HTTPClient,
	}, nil
}

// Name identifies this exporter in logs.
func (s *ServiceNowExporter) Name() string { return "servicenow" }

// PushIndicators POSTs one record per agent rollup to the indicator table.
func (s *ServiceNowExporter) PushIndicators(ctx context.Context, inds []RiskIndicator) error {
	endpoint := s.base + "/api/now/table/" + url.PathEscape(s.indTable)
	var firstErr error
	for _, r := range inds {
		body := map[string]any{
			"short_description": fmt.Sprintf("IntentGate risk indicator: %s (%d/%d blocked)", agentLabel(r.AgentID), r.Deny, r.Total),
			"u_agent_id":        r.AgentID,
			"u_tenant":          r.Tenant,
			"u_allow":           r.Allow,
			"u_deny":            r.Deny,
			"u_escalate":        r.Escalate,
			"u_total":           r.Total,
			"u_block_rate":      fmt.Sprintf("%.4f", r.BlockRate()),
			"u_window_start":    r.WindowStart.UTC().Format(time.RFC3339),
			"u_window_end":      r.WindowEnd.UTC().Format(time.RFC3339),
			"u_source":          "IntentGate",
		}
		if err := s.post(ctx, endpoint, body); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// OpenIssue POSTs a threshold breach to the issue table.
func (s *ServiceNowExporter) OpenIssue(ctx context.Context, issue RiskIssue) error {
	endpoint := s.base + "/api/now/table/" + url.PathEscape(s.issueTbl)
	desc := fmt.Sprintf(
		"IntentGate detected %d blocked actions for agent %s in one window (%s–%s).\nCategory: %s\nReason: %s",
		issue.DenyCount, agentLabel(issue.AgentID),
		issue.WindowStart.UTC().Format(time.RFC3339), issue.WindowEnd.UTC().Format(time.RFC3339),
		issue.Category, issue.Reason,
	)
	if issue.ProofSHA256 != "" {
		desc += "\nProof (result_sha256): " + issue.ProofSHA256
	}
	body := map[string]any{
		"short_description": fmt.Sprintf("IntentGate risk issue: %s exceeded block threshold", agentLabel(issue.AgentID)),
		"description":       desc,
		"u_agent_id":        issue.AgentID,
		"u_tenant":          issue.Tenant,
		"u_category":        issue.Category,
		"u_deny_count":      issue.DenyCount,
		"u_source":          "IntentGate",
	}
	if issue.ProofSHA256 != "" {
		body["u_proof_sha256"] = issue.ProofSHA256
	}
	return s.post(ctx, endpoint, body)
}

func (s *ServiceNowExporter) post(ctx context.Context, endpoint string, body map[string]any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("riskregister/servicenow: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("riskregister/servicenow: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := s.authorize(ctx, req); err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("riskregister/servicenow: table API returned %d", resp.StatusCode)
	}
	return nil
}

func (s *ServiceNowExporter) authorize(ctx context.Context, req *http.Request) error {
	if s.cfg.ClientID != "" && s.cfg.ClientSecret != "" {
		tok, err := s.oauthToken(ctx)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
	req.SetBasicAuth(s.cfg.Username, s.cfg.Password)
	return nil
}

func (s *ServiceNowExporter) oauthToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.tokenAt) {
		return s.token, nil
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/oauth_token.do", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("riskregister/servicenow: oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("riskregister/servicenow: oauth: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("riskregister/servicenow: oauth token endpoint returned %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("riskregister/servicenow: oauth decode: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("riskregister/servicenow: empty access_token")
	}
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 1800
	}
	s.token = tr.AccessToken
	s.tokenAt = time.Now().Add(time.Duration(ttl-60) * time.Second)
	return s.token, nil
}

func agentLabel(id string) string {
	if id == "" {
		return "(unknown agent)"
	}
	return id
}

// Compile-time proof the exporter satisfies the seam.
var _ Exporter = (*ServiceNowExporter)(nil)
