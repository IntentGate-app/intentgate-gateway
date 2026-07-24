package siem

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

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// ServiceNowTarget selects which ServiceNow table (and therefore which
// field mapping) audit events land in. The adapter is deliberately
// multi-target because ServiceNow licensing differs widely across
// customers: GRC/IRM and Security Incident Response are premium modules,
// while the base `incident` table exists on every instance. Hardcoding
// one would either lock out customers without the license or clog the IT
// helpdesk with runtime audit volume, so the destination is a config
// choice, not a build-time decision.
type ServiceNowTarget string

const (
	// TargetGRC writes control evidence into the IRM/GRC evidence table.
	// Default enterprise profile: continuous automated compliance.
	TargetGRC ServiceNowTarget = "grc"
	// TargetSIR writes Security Incident Response records. For SOCs that
	// run inside ServiceNow SIR.
	TargetSIR ServiceNowTarget = "sir"
	// TargetITSM writes plain ITSM incidents. Universal fallback — works
	// on any instance without GRC/SIR licensing.
	TargetITSM ServiceNowTarget = "itsm"
	// TargetCustom writes to a customer scoped table (Table.Custom),
	// e.g. an IntentGate Store App table, leaving routing to ServiceNow
	// Flow Designer / Business Rules.
	TargetCustom ServiceNowTarget = "custom"
)

// defaultTables maps each target to the ServiceNow table the adapter
// POSTs to. The exact GRC evidence table name varies by instance and
// scoped-app install, so ServiceNowConfig.Table overrides any default.
var defaultTables = map[ServiceNowTarget]string{
	TargetGRC:  "sn_compliance_evidence",
	TargetSIR:  "sn_si_incident",
	TargetITSM: "incident",
}

// severity is the internal risk ordering derived from the decision, used
// only for the MinSeverity gate and to fill ServiceNow priority/urgency.
type severity int

const (
	sevLow severity = iota
	sevMedium
	sevHigh
)

func decisionSeverity(d audit.Decision) severity {
	switch d {
	case audit.DecisionBlock:
		return sevHigh
	case audit.DecisionEscalate:
		return sevMedium
	default:
		return sevLow
	}
}

func parseSeverity(s string) severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return sevHigh
	case "medium", "med":
		return sevMedium
	default:
		return sevLow
	}
}

// ServiceNowConfig configures the ServiceNow Table API adapter.
//
// It is a Lightweight-to-Enterprise GRC sink on the async path: audit
// events are POSTed to the ServiceNow Table API after the firewall
// decision has already returned, so a slow or unreachable instance can
// never add latency to (or block) an agent's tool call — the shared
// batch worker drops on a full buffer rather than waiting.
type ServiceNowConfig struct {
	// InstanceURL is the base instance, e.g. "https://acme.service-now.com".
	// Required. A trailing slash is tolerated.
	InstanceURL string
	// Target selects the table + field mapping. Defaults to TargetGRC.
	Target ServiceNowTarget
	// Table overrides the destination table for the chosen target. Required
	// when Target is TargetCustom; otherwise falls back to defaultTables.
	Table string

	// --- Auth. Basic when Username/Password set; OAuth2 client-credentials
	// when ClientID/ClientSecret set. OAuth2 takes precedence. ---
	Username     string
	Password     string
	ClientID     string
	ClientSecret string

	// MinSeverity gates what is offloaded: "low" (everything), "medium"
	// (escalations + blocks), or "high" (blocks only). Keeps the
	// ServiceNow API quota from being saturated by routine allows.
	// Defaults to "low".
	MinSeverity string
	// IncludeAllows, when false (the default), drops ALLOW decisions
	// entirely — SIR/ITSM queues want findings, not the full stream.
	IncludeAllows bool
	// IncludeProofHashes, when true (the default), carries the
	// result_sha256 proof hash into the record body.
	IncludeProofHashes bool
	// CallbackBaseURL is the IntentGate control-plane base a ServiceNow
	// MID Server / Flow calls back to resume a held decision, e.g.
	// "https://gateway.internal.net". When set, ESCALATE (HOLD) records
	// carry a machine-readable IntentGate-Data block with the decision id,
	// the required action, and the resume callback URL
	// (<base>/v1/approvals/<event_id>) so a ServiceNow approval can drive
	// Phase 4 (control-plane resume). Empty omits the callback block.
	CallbackBaseURL string

	// HTTPClient is injected in tests; nil falls back to a default client
	// with a 30-second total timeout.
	HTTPClient *http.Client
	// Logger receives drop / error notices. nil falls back to slog.Default.
	Logger *slog.Logger
}

// ServiceNowEmitter ships audit events to the ServiceNow Table API as
// control evidence, security incidents, or ITSM incidents, one record
// per event. It reuses the shared batch worker for the same
// non-blocking, drops-not-blocks contract every adapter shares.
type ServiceNowEmitter struct {
	cfg     ServiceNowConfig
	be      *batchEmitter
	name    string
	base    string
	table   string
	minSev severity
	label  string

	// OAuth2 token cache.
	mu      sync.Mutex
	token   string
	tokenAt time.Time // expiry
}

// NewServiceNowEmitter validates config, builds the emitter, and starts
// its worker.
func NewServiceNowEmitter(cfg ServiceNowConfig) (*ServiceNowEmitter, error) {
	if strings.TrimSpace(cfg.InstanceURL) == "" {
		return nil, errors.New("siem/servicenow: InstanceURL is required")
	}
	if cfg.Target == "" {
		cfg.Target = TargetGRC
	}
	table := strings.TrimSpace(cfg.Table)
	if table == "" {
		if cfg.Target == TargetCustom {
			return nil, errors.New("siem/servicenow: Table is required when Target is \"custom\"")
		}
		table = defaultTables[cfg.Target]
	}
	if table == "" {
		return nil, fmt.Errorf("siem/servicenow: unknown target %q", cfg.Target)
	}
	oauth := cfg.ClientID != "" && cfg.ClientSecret != ""
	basic := cfg.Username != "" && cfg.Password != ""
	if !oauth && !basic {
		return nil, errors.New("siem/servicenow: set either Username/Password (basic) or ClientID/ClientSecret (oauth2)")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	sn := &ServiceNowEmitter{
		cfg:     cfg,
		name:    "servicenow",
		base:    strings.TrimRight(strings.TrimSpace(cfg.InstanceURL), "/"),
		table:   table,
		minSev:  parseSeverity(cfg.MinSeverity),
		useAuth: true,
	}
	sn.label = sn.base + " → " + string(cfg.Target) + ":" + table
	sn.be = newBatchEmitter(batchConfig{
		Name:   sn.name,
		Flush:  sn.flush,
		Logger: cfg.Logger,
	})
	return sn, nil
}

// Emit applies the severity / allow filter, then forwards the event to
// the batched worker. Filtering here (not in the worker) keeps the
// buffer from filling with events that would be dropped anyway.
func (s *ServiceNowEmitter) Emit(ctx context.Context, ev audit.Event) {
	if !s.cfg.IncludeAllows && ev.Decision == audit.DecisionAllow {
		return
	}
	if decisionSeverity(ev.Decision) < s.minSev {
		return
	}
	s.be.Emit(ctx, ev)
}

// Stop drains the worker.
func (s *ServiceNowEmitter) Stop(ctx context.Context) error { return s.be.Stop(ctx) }

// Status snapshots the emitter for the admin endpoint. The instance +
// target/table label is exposed; credentials never are.
func (s *ServiceNowEmitter) Status() Status {
	return s.be.snapshot(s.name, s.label, true)
}

// flush POSTs each event as its own ServiceNow record (the Table API is
// one-record-per-POST). A per-record error is returned to the worker,
// which logs it and clears the batch rather than blocking the gateway.
func (s *ServiceNowEmitter) flush(ctx context.Context, events []audit.Event) error {
	endpoint := s.base + "/api/now/table/" + url.PathEscape(s.table)
	var firstErr error
	for _, ev := range events {
		body, err := json.Marshal(s.mapRecord(ev))
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("siem/servicenow: marshal: %w", err)
			}
			continue
		}
		if err := s.postRecord(ctx, endpoint, body); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

func (s *ServiceNowEmitter) postRecord(ctx context.Context, endpoint string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("siem/servicenow: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := s.authorize(ctx, req); err != nil {
		return err
	}
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		// Token may have expired; drop the cache so the next flush refetches.
		s.mu.Lock()
		s.token = ""
		s.mu.Unlock()
		return &permanentHTTPError{status: resp.StatusCode}
	}
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
		return &transientHTTPError{status: resp.StatusCode}
	}
	if resp.StatusCode >= 400 {
		return &permanentHTTPError{status: resp.StatusCode}
	}
	return nil
}

// authorize attaches OAuth2 bearer (preferred) or HTTP basic auth.
func (s *ServiceNowEmitter) authorize(ctx context.Context, req *http.Request) error {
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

// oauthToken returns a cached client-credentials access token, fetching a
// fresh one (and caching it until shortly before expiry) when needed.
func (s *ServiceNowEmitter) oauthToken(ctx context.Context) (string, error) {
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
		return "", fmt.Errorf("siem/servicenow: oauth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("siem/servicenow: oauth: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("siem/servicenow: oauth token endpoint returned %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("siem/servicenow: oauth decode: %w", err)
	}
	if tr.AccessToken == "" {
		return "", errors.New("siem/servicenow: oauth token endpoint returned empty access_token")
	}
	ttl := tr.ExpiresIn
	if ttl <= 0 {
		ttl = 1800 // ServiceNow default access-token lifetime is 30 min.
	}
	s.token = tr.AccessToken
	// Refresh a minute early to avoid racing expiry mid-flush.
	s.tokenAt = time.Now().Add(time.Duration(ttl-60) * time.Second)
	return s.token, nil
}

// mapRecord builds the ServiceNow record body for one event, per the
// chosen target's field mapping.
func (s *ServiceNowEmitter) mapRecord(ev audit.Event) map[string]any {
	summary := ev.Summary
	if summary == "" {
		summary = BuildSummary(ev)
	}
	short := fmt.Sprintf("IntentGate Audit Proof: %s -> %s", firstNonEmpty(ev.AgentID, "unknown-agent"), firstNonEmpty(ev.Tool, "unknown-tool"))

	// A human-readable body common to every target.
	var desc strings.Builder
	desc.WriteString(summary)
	desc.WriteString("\n\n")
	fmt.Fprintf(&desc, "Decision: %s\n", ev.Decision)
	if ev.Check != "" {
		fmt.Fprintf(&desc, "Check: %s\n", ev.Check)
	}
	if ev.Reason != "" {
		fmt.Fprintf(&desc, "Reason: %s\n", ev.Reason)
	}
	if ev.AgentID != "" {
		fmt.Fprintf(&desc, "Agent: %s\n", ev.AgentID)
	}
	if ev.Tenant != "" {
		fmt.Fprintf(&desc, "Tenant: %s\n", ev.Tenant)
	}
	if ev.EventID != "" {
		fmt.Fprintf(&desc, "Event ID: %s\n", ev.EventID)
	}
	if s.cfg.IncludeProofHashes && ev.ResultSHA256 != "" {
		fmt.Fprintf(&desc, "Proof (result_sha256): %s\n", ev.ResultSHA256)
	}

	// Machine-readable block a ServiceNow Flow / Business Rule can parse
	// to drive the human-in-the-loop resume (Phase 4). Only stamped on
	// held decisions when a control-plane callback base is configured.
	if cb := s.callbackData(ev); cb != nil {
		if b, err := json.Marshal(cb); err == nil {
			fmt.Fprintf(&desc, "\nIntentGate-Data: %s\n", b)
		}
	}

	switch s.cfg.Target {
	case TargetGRC:
		rec := map[string]any{
			"short_description": short,
			"description":       desc.String(),
			"state":             grcState(ev.Decision),
			"attestation_type":  "Automated Evidence",
		}
		if s.cfg.IncludeProofHashes && ev.ResultSHA256 != "" {
			rec["u_proof_sha256"] = ev.ResultSHA256
		}
		return rec

	case TargetSIR:
		return map[string]any{
			"short_description": short,
			"description":       desc.String(),
			"category":          "AI / Autonomous Agent Security",
			"priority":          sirPriority(ev.Decision),
		}

	case TargetITSM:
		u, i := itsmUrgencyImpact(decisionSeverity(ev.Decision))
		return map[string]any{
			"short_description": short,
			"description":       desc.String(),
			"category":          "Software / AI Gatekeeper",
			"urgency":           u,
			"impact":            i,
		}

	default: // TargetCustom — structured, unopinionated.
		rec := map[string]any{
			"u_short_description": short,
			"u_summary":           summary,
			"u_decision":          string(ev.Decision),
			"u_tool":              ev.Tool,
			"u_agent_id":          ev.AgentID,
			"u_tenant":            ev.Tenant,
			"u_event_id":          ev.EventID,
			"u_check":             string(ev.Check),
			"u_reason":            ev.Reason,
			"u_timestamp":         ev.Timestamp,
		}
		if s.cfg.IncludeProofHashes && ev.ResultSHA256 != "" {
			rec["u_proof_sha256"] = ev.ResultSHA256
		}
		return rec
	}
}

// callbackData returns the machine-readable Phase-4 resume block for a
// held (ESCALATE) decision, or nil when no callback should be stamped
// (not a hold, no control-plane base configured, or no event id to
// resume against). The shape is stable so a ServiceNow Flow can parse it.
func (s *ServiceNowEmitter) callbackData(ev audit.Event) map[string]any {
	if s.cfg.CallbackBaseURL == "" || ev.Decision != audit.DecisionEscalate || ev.EventID == "" {
		return nil
	}
	base := strings.TrimRight(strings.TrimSpace(s.cfg.CallbackBaseURL), "/")
	cb := map[string]any{
		"event_type":      "INTENTGATE_POLICY_HOLD",
		"decision_id":     ev.EventID,
		"tenant_id":       ev.Tenant,
		"agent_id":        ev.AgentID,
		"target_tool":     ev.Tool,
		"risk_score":      strings.ToUpper(severityLabel(decisionSeverity(ev.Decision))),
		"policy_rule":     ev.Reason,
		"action_required": "HUMAN_APPROVAL",
		"callback_url":    base + "/v1/approvals/" + url.PathEscape(ev.EventID),
	}
	if s.cfg.IncludeProofHashes && ev.ResultSHA256 != "" {
		cb["proof_of_intent_hash"] = ev.ResultSHA256
	}
	return cb
}

func severityLabel(sev severity) string {
	switch sev {
	case sevHigh:
		return "high"
	case sevMedium:
		return "medium"
	default:
		return "low"
	}
}

// grcState maps a decision onto the evidence record state: an allow is
// satisfied evidence; a block or escalation raises an issue.
func grcState(d audit.Decision) string {
	if d == audit.DecisionAllow {
		return "Satisfied"
	}
	return "Issue Generated"
}

// sirPriority maps a decision onto ServiceNow's numeric priority
// ("1"–"5", 1 = Critical). Blocks are critical, escalations high.
func sirPriority(d audit.Decision) string {
	switch d {
	case audit.DecisionBlock:
		return "1"
	case audit.DecisionEscalate:
		return "2"
	default:
		return "4"
	}
}

// itsmUrgencyImpact maps severity onto ServiceNow's urgency/impact
// scale ("1" high … "3" low), which together drive the derived priority.
func itsmUrgencyImpact(sev severity) (string, string) {
	switch sev {
	case sevHigh:
		return "1", "1"
	case sevMedium:
		return "2", "2"
	default:
		return "3", "3"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
