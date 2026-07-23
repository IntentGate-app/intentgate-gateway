package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/auditstore"
	poi "github.com/IntentGate-app/intentgate-gateway/internal/proofofintent"
)

// NewAdminProofOfIntentHandler serves POST /v1/admin/proof-of-intent: it reads
// the audit events for a session or a single decision and returns a signed,
// tamper-evident evidence bundle (internal/proofofintent). It does not touch
// the request path - it reads the audit trail the gateway already keeps and
// signs a bundle with the gateway master key. Same auth + tenant scoping as the
// other audit-store-backed admin endpoints.
func NewAdminProofOfIntentHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStore == nil {
			adminError(w, http.StatusServiceUnavailable, "audit store not configured")
			return
		}
		if len(cfg.MasterKey) == 0 {
			adminError(w, http.StatusServiceUnavailable, "master key not configured")
			return
		}

		var body struct {
			SessionID string `json:"session_id"`
			EventID   string `json:"event_id"`
			Tenant    string `json:"tenant"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if body.SessionID == "" && body.EventID == "" {
			adminError(w, http.StatusBadRequest, "session_id or event_id is required")
			return
		}

		// Tenant scoping: a per-tenant admin is forced to its own tenant; a
		// superadmin may pass one explicitly.
		tenant := body.Tenant
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden, "tenant does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		// The store has no session/event equality filter, so pull a
		// tenant-scoped page and match in-handler. Capped at the store max.
		events, err := cfg.AuditStore.Query(r.Context(), auditstore.QueryFilter{Tenant: tenant, Limit: 1000})
		if err != nil {
			cfg.Logger.Error("proof-of-intent query failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		subject := body.SessionID
		if subject == "" {
			subject = body.EventID
		}

		var matched []poi.Entry
		for _, e := range events {
			if body.SessionID != "" && e.SessionID != body.SessionID {
				continue
			}
			if body.EventID != "" && e.EventID != body.EventID {
				continue
			}
			matched = append(matched, poi.Entry{
				EventID:       e.EventID,
				Ts:            e.Timestamp,
				Agent:         e.AgentID,
				Tool:          e.Tool,
				Decision:      string(e.Decision),
				Check:         string(e.Check),
				Reason:        e.Reason,
				IntentSummary: e.IntentSummary,
				ResultSHA256:  e.ResultSHA256,
				// PrevHash / Hash are stored on the DB row, not on the queried
				// Event, so they are left empty; the HMAC signature is the proof.
			})
		}
		if len(matched) == 0 {
			adminError(w, http.StatusNotFound, "no audit events found for that subject")
			return
		}

		// Query returns newest-first; a bundle reads oldest-first.
		sort.SliceStable(matched, func(i, j int) bool { return matched[i].Ts < matched[j].Ts })

		bundle := poi.Build(tenant, subject, matched, time.Now())
		if err := poi.Sign(&bundle, "master-hmac-v1", cfg.MasterKey); err != nil {
			adminError(w, http.StatusInternalServerError, "sign failed: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(bundle)
	})
}
