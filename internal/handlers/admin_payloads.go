package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/payloads"
)

// NewAdminPayloadHandler returns GET /v1/admin/payloads/{event_id}.
//
// This is the door into retained customer data, and it is built to be the most
// heavily constrained endpoint in the admin API.
//
// # Every read is itself an audited event
//
// Fetching a payload is access to what a customer's agent actually received,
// so it emits its own audit event (`payload_read`) before returning anything.
// A payload store that anyone with an admin token can browse silently is a
// shadow copy of the customer's data with no trail, which is a worse liability
// than not retaining it at all. The read is audited whether it succeeds or
// fails: an attempt to read a payload is worth recording even when there was
// nothing there.
//
// # Tenant scoping is enforced, not advisory
//
// A per-tenant admin can only read payloads for their own tenant. A superadmin
// must name the tenant explicitly via ?tenant=; there is deliberately no
// "search every tenant" mode, because a cross-tenant sweep is exactly the
// shape of the incident this design exists to prevent.
func NewAdminPayloadHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodGet {
			adminError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Payloads == nil {
			// Distinct from "not found": the operator needs to know capture is
			// not configured, rather than conclude this particular call had no
			// response worth keeping.
			adminError(w, http.StatusNotFound, "response capture is not enabled on this gateway")
			return
		}

		eventID := strings.TrimPrefix(r.URL.Path, "/v1/admin/payloads/")
		eventID = strings.Trim(eventID, "/")
		if eventID == "" || strings.Contains(eventID, "/") {
			adminError(w, http.StatusBadRequest, "expected /v1/admin/payloads/{event_id}")
			return
		}

		// Resolve the tenant. A per-tenant admin is pinned to their own; a
		// superadmin must say which one.
		tenant := auth.tenant
		if tenant == "" {
			tenant = strings.TrimSpace(r.URL.Query().Get("tenant"))
			if tenant == "" && len(cfg.TenantAdmins) > 0 {
				adminError(w, http.StatusBadRequest,
					"tenant is required: pass ?tenant= to name the tenant whose payload you are reading")
				return
			}
		} else if q := strings.TrimSpace(r.URL.Query().Get("tenant")); q != "" && q != tenant {
			// A tenant admin asking for someone else's data is not a mistake
			// worth silently correcting.
			adminError(w, http.StatusForbidden, "not permitted to read payloads for another tenant")
			return
		}

		rec, err := cfg.Payloads.Get(r.Context(), tenant, eventID)
		found := err == nil

		// Audit BEFORE writing the body. If the process dies mid-response the
		// record of the attempt still exists; the alternative loses exactly
		// the reads someone would most want to find later.
		cfg.emitPayloadRead(r, tenant, eventID, found, err)

		if errors.Is(err, payloads.ErrNotFound) {
			adminError(w, http.StatusNotFound,
				"no retained payload for that event: it was never captured, or its retention period has passed")
			return
		}
		if err != nil {
			cfg.Logger.Error("payload read failed", "event_id", eventID, "err", err)
			adminError(w, http.StatusInternalServerError, "could not read the payload")
			return
		}

		// body is returned as a raw JSON message when it parses as JSON, so a
		// console can render it structurally rather than as an escaped string.
		var body json.RawMessage
		if json.Valid(rec.Body) {
			body = json.RawMessage(rec.Body)
		} else {
			b, _ := json.Marshal(string(rec.Body))
			body = json.RawMessage(b)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"event_id":    rec.EventID,
			"tenant":      rec.Tenant,
			"agent_id":    rec.AgentID,
			"tool":        rec.Tool,
			"raw_sha256":  rec.RawSHA256,
			"raw_bytes":   rec.RawBytes,
			"redacted":    rec.Redacted,
			"captured_at": rec.CapturedAt.UTC().Format(time.RFC3339),
			"expires_at":  rec.ExpiresAt.UTC().Format(time.RFC3339),
			"body":        body,
			// Say plainly what this is, so a reader of the raw API response
			// does not mistake the stored body for what the upstream sent.
			"note": "this is the redacted response as the agent received it; raw_sha256 is the hash of the unredacted upstream response, which is not stored",
		})
	})
}

// emitPayloadRead records that someone looked at retained customer data.
//
// The event carries who asked (by admin identity, not by agent), which payload
// and whether it was there. It deliberately carries nothing from the body: an
// audit trail that quotes the data it is protecting has defeated itself, and
// this event goes to the same SIEMs as every other audit record.
func (cfg AdminConfig) emitPayloadRead(
	r *http.Request,
	tenant, eventID string,
	found bool,
	readErr error,
) {
	if cfg.Audit == nil {
		return
	}
	reason := "payload read"
	switch {
	case errors.Is(readErr, payloads.ErrNotFound):
		reason = "payload read: no retained payload for that event"
	case readErr != nil:
		reason = "payload read failed"
	}

	e := audit.NewEvent(audit.DecisionAllow, "admin/payload_read")
	e.EventName = "payload_read"
	e.Reason = reason
	e.Tenant = tenant
	e.RemoteIP = r.RemoteAddr
	// The subject of the read, so an investigator can join this back to the
	// decision whose response was inspected.
	e.CapabilityTokenID = eventID
	e.ResultStored = found
	if actor := strings.TrimSpace(r.Header.Get("X-IntentGate-Actor")); actor != "" {
		// Console-pro sets this to the signed-in operator. Absent on a raw
		// curl with the admin token, which is itself worth seeing in the log.
		e.AgentID = actor
	} else {
		e.AgentID = "admin-token"
	}
	cfg.Audit.Emit(r.Context(), e)
}
