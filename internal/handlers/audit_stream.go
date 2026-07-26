package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// NewAdminAuditStreamHandler serves the live decision stream as Server-Sent
// Events at GET /v1/admin/audit/stream. It is the push counterpart to the
// polled /v1/admin/audit query: the Runtime Monitor opens one EventSource and
// receives each decision the moment it is recorded, instead of re-fetching on
// a timer.
//
// It reads from the in-memory [audit.StreamHub], which sits in the audit
// fan-out and never touches the inline decision path, so a connected browser
// can never slow enforcement. Tenant scoping matches the query endpoint: a
// per-tenant admin token is confined to its tenant; a superadmin may pass
// ?tenant= to narrow. Reconnect is loss-free: the browser resends the last
// event id it saw (SSE Last-Event-ID header, or a ?last_event_id= fallback)
// and the handler replays exactly the events after it from the hub's ring.
func NewAdminAuditStreamHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.AuditStream == nil {
			adminError(w, http.StatusServiceUnavailable, "audit stream not enabled")
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			adminError(w, http.StatusInternalServerError, "streaming unsupported by this server")
			return
		}

		// Tenant scope. Per-tenant admin is forced to its own tenant; a
		// superadmin may narrow with ?tenant=. Empty means all tenants.
		tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden,
					"tenant in query does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		// Resume point. The SSE spec sends it as the Last-Event-ID header on
		// reconnect; accept a query-string fallback for clients that cannot
		// set headers on an EventSource.
		var afterSeq uint64
		if v := strings.TrimSpace(r.Header.Get("Last-Event-ID")); v != "" {
			afterSeq, _ = strconv.ParseUint(v, 10, 64)
		} else if v := strings.TrimSpace(r.URL.Query().Get("last_event_id")); v != "" {
			afterSeq, _ = strconv.ParseUint(v, 10, 64)
		}

		h := w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		h.Set("Connection", "keep-alive")
		// Ask intermediary proxies (nginx) not to buffer the stream, which
		// would otherwise hold frames until the connection closed.
		h.Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		replay, ch, cancel := cfg.AuditStream.Subscribe(afterSeq, 256)
		defer cancel()

		// write emits one SSE frame per event, skipping events outside the
		// tenant scope. Returns false when the socket can no longer be
		// written, which ends the stream.
		write := func(se audit.StreamEvent) bool {
			if tenant != "" && se.Event.Tenant != tenant {
				return true // filtered out, but the connection is still healthy
			}
			b, err := json.Marshal(se.Event)
			if err != nil {
				return true // skip an unserializable event rather than drop the client
			}
			if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", se.Seq, b); err != nil {
				return false
			}
			flusher.Flush()
			return true
		}

		// Replay anything missed since the resume point, then open the live
		// stream with a comment frame so the client's onopen fires promptly.
		for _, se := range replay {
			if !write(se) {
				return
			}
		}
		if _, err := fmt.Fprint(w, ": connected\n\n"); err != nil {
			return
		}
		flusher.Flush()

		// Heartbeat comments keep idle connections (and the proxies between)
		// from timing out when no decisions are flowing.
		heartbeat := time.NewTicker(15 * time.Second)
		defer heartbeat.Stop()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case se, open := <-ch:
				if !open {
					return
				}
				if !write(se) {
					return
				}
			case <-heartbeat.C:
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				flusher.Flush()
			}
		}
	})
}
