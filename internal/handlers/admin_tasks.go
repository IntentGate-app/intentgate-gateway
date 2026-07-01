package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/task"
)

// NewAdminTasksListHandler returns GET /v1/admin/tasks. Lists bound
// tasks (goal-drift state), most-recently-updated first. Superadmin
// sees all; a per-tenant admin sees only its own tenant's tasks. Query
// params: limit (default 100, max 1000), offset (default 0).
func NewAdminTasksListHandler(cfg AdminConfig) http.Handler {
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
		if cfg.Tasks == nil {
			adminError(w, http.StatusServiceUnavailable, "task binding not configured")
			return
		}
		limit := parseIntParam(r, "limit", 100, 1, 1000)
		offset := parseIntParam(r, "offset", 0, 0, 1<<31-1)

		list, err := cfg.Tasks.List(r.Context(), auth.tenant, limit, offset)
		if err != nil {
			cfg.Logger.Error("task list failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": list})
	})
}

// NewAdminTaskClearHandler returns POST /v1/admin/tasks/clear. Clears a
// task's drift and returns it to active — the operator's "I have
// reviewed this, resume it" control after a task was flagged or halted.
//
// Body: {"id": "<task id>"}. Tenant is taken from the caller's admin
// scope, so a per-tenant admin can only clear its own tasks.
func NewAdminTaskClearHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Tasks == nil {
			adminError(w, http.StatusServiceUnavailable, "task binding not configured")
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.ID) == "" {
			adminError(w, http.StatusBadRequest, "id is required")
			return
		}

		t, err := cfg.Tasks.Get(r.Context(), auth.tenant, body.ID)
		if err != nil {
			cfg.Logger.Error("task get failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		if t == nil {
			adminError(w, http.StatusNotFound, "task not found")
			return
		}
		t.Drift = 0
		t.Status = task.StatusActive
		t.UpdatedAt = time.Now().UTC()
		if err := cfg.Tasks.Upsert(r.Context(), t); err != nil {
			cfg.Logger.Error("task clear failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		ev := audit.NewEvent(audit.DecisionAllow, "admin/tasks/clear")
		ev.Check = audit.CheckIntent
		ev.Reason = "task drift cleared"
		ev.AgentID = t.Agent
		ev.Tenant = t.Tenant
		ev.RemoteIP = r.RemoteAddr
		ev.ElevationID = resolveElevationID(r)
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("task drift cleared", "id", body.ID, "by", auth.tenant)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
}
