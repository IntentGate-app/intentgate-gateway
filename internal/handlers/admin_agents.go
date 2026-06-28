package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/auditstore"
	"github.com/IntentGate-app/intentgate-gateway/internal/discovery"
)

// NewAdminAgentsHandler returns the GET /v1/admin/agents handler:
// passive agent discovery built from observed audit traffic.
//
// It pages the audit store, aggregates events into the set of distinct
// agents (the tools each called, call/blocked counts, first/last seen,
// derived risk signals), and returns them most-recently-seen first.
// No persistence of its own — discovery is a read over the audit log,
// so it reflects whatever the gateway has actually seen.
//
// Auth + tenant scoping mirror /v1/admin/audit exactly: a per-tenant
// admin token forces its tenant; superadmin may pass ?tenant=. Optional
// ?from= / ?to= RFC3339 bounds narrow the window.
//
// Response:
//
//	{
//	  "agents": [ { agent_id, tenant, tools, risk_signals, calls,
//	                blocked, first_seen, last_seen, session_count }, ... ],
//	  "events_scanned": 1234
//	}
//
// 401 bad auth, 503 when the audit store isn't configured, 400 on a bad
// timestamp.
func NewAdminAgentsHandler(cfg AdminConfig) http.Handler {
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

		q := r.URL.Query()
		tenant := q.Get("tenant")
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		filter := auditstore.QueryFilter{Tenant: tenant}
		if from := q.Get("from"); from != "" {
			t, err := time.Parse(time.RFC3339, from)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'from' timestamp: "+err.Error())
				return
			}
			filter.From = t.UTC()
		}
		if to := q.Get("to"); to != "" {
			t, err := time.Parse(time.RFC3339, to)
			if err != nil {
				adminError(w, http.StatusBadRequest, "invalid 'to' timestamp: "+err.Error())
				return
			}
			filter.To = t.UTC()
		}

		// Page the store so discovery sees more than one page of
		// traffic. Bounded so a busy deployment can't turn a single
		// discovery call into an unbounded scan.
		const pageSize = 1000
		const maxEvents = 10000
		var all []audit.Event
		offset := 0
		for len(all) < maxEvents {
			f := filter
			f.Limit = pageSize
			f.Offset = offset
			events, err := cfg.AuditStore.Query(r.Context(), f)
			if err != nil {
				cfg.Logger.Error("agent discovery query failed", "err", err)
				adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
				return
			}
			all = append(all, events...)
			if len(events) < pageSize {
				break
			}
			offset += pageSize
		}

		agents := discovery.Aggregate(all)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agents":         agents,
			"events_scanned": len(all),
		})
	})
}
