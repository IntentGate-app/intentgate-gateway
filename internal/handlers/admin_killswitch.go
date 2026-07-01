package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/killswitch"
)

// killSwitchBody is the request shape for engage and release.
//
//	{"scope":"global|tenant|agent", "tenant":"...", "value":"<agent id>", "reason":"..."}
//
// Authorization narrows what a caller may target:
//   - Superadmin (auth.tenant == "") may engage any scope. For tenant
//     and agent scopes it must name the target tenant.
//   - A per-tenant admin may only engage tenant or agent kills within
//     its own tenant; the tenant field is forced to the admin's tenant
//     and a global request is rejected.
type killSwitchBody struct {
	Scope  string `json:"scope"`
	Tenant string `json:"tenant"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// resolveKillEntry applies the authorization rules and returns the
// effective entry to engage or release, or an error message (with the
// HTTP status the caller should return).
func resolveKillEntry(b killSwitchBody, auth adminAuth) (killswitch.Entry, int, string) {
	scope := killswitch.ScopeType(strings.TrimSpace(b.Scope))
	e := killswitch.Entry{Type: scope, Reason: strings.TrimSpace(b.Reason), SetBy: auth.tenant}

	switch scope {
	case killswitch.ScopeGlobal:
		if auth.tenant != "" {
			return e, http.StatusForbidden, "only the superadmin may engage a global kill"
		}
	case killswitch.ScopeTenant:
		if auth.tenant == "" {
			// superadmin must name the tenant
			if strings.TrimSpace(b.Tenant) == "" {
				return e, http.StatusBadRequest, "tenant is required for a tenant kill"
			}
			e.Tenant = strings.TrimSpace(b.Tenant)
		} else {
			// per-tenant admin: forced to own tenant
			e.Tenant = auth.tenant
		}
	case killswitch.ScopeAgent:
		if strings.TrimSpace(b.Value) == "" {
			return e, http.StatusBadRequest, "value (agent id) is required for an agent kill"
		}
		e.Value = strings.TrimSpace(b.Value)
		if auth.tenant == "" {
			if strings.TrimSpace(b.Tenant) == "" {
				return e, http.StatusBadRequest, "tenant is required for an agent kill"
			}
			e.Tenant = strings.TrimSpace(b.Tenant)
		} else {
			e.Tenant = auth.tenant
		}
	default:
		return e, http.StatusBadRequest, "scope must be one of: global, tenant, agent"
	}
	if err := e.Validate(); err != nil {
		return e, http.StatusBadRequest, "invalid scope combination"
	}
	return e, http.StatusOK, ""
}

// NewAdminKillSwitchEngageHandler returns POST /v1/admin/kill-switch.
// Engages a kill. On success returns 200 {"ok":true}. Idempotent.
func NewAdminKillSwitchEngageHandler(cfg AdminConfig) http.Handler {
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
		if cfg.KillSwitch == nil {
			adminError(w, http.StatusServiceUnavailable, "kill switch not configured")
			return
		}
		var body killSwitchBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		entry, status, msg := resolveKillEntry(body, auth)
		if status != http.StatusOK {
			adminError(w, status, msg)
			return
		}
		if err := cfg.KillSwitch.Engage(r.Context(), entry); err != nil {
			cfg.Logger.Error("kill-switch engage failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		ev := audit.NewEvent(audit.DecisionBlock, "admin/kill-switch/engage")
		ev.Check = audit.CheckCapability
		ev.Reason = "kill switch engaged (" + string(entry.Type) + "): " + entry.Reason
		ev.AgentID = entry.Value
		ev.Tenant = entry.Tenant
		ev.RemoteIP = r.RemoteAddr
		ev.ElevationID = resolveElevationID(r)
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Warn("kill switch engaged",
			"scope", entry.Type, "tenant", entry.Tenant, "agent", entry.Value,
			"reason", entry.Reason, "by", auth.tenant)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "entry": entry})
	})
}

// NewAdminKillSwitchReleaseHandler returns POST
// /v1/admin/kill-switch/release. Releases a kill. Same authorization
// rules as engage. Idempotent: releasing a kill that is not engaged is
// not an error.
func NewAdminKillSwitchReleaseHandler(cfg AdminConfig) http.Handler {
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
		if cfg.KillSwitch == nil {
			adminError(w, http.StatusServiceUnavailable, "kill switch not configured")
			return
		}
		var body killSwitchBody
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		entry, status, msg := resolveKillEntry(body, auth)
		if status != http.StatusOK {
			adminError(w, status, msg)
			return
		}
		if err := cfg.KillSwitch.Release(r.Context(), entry.Type, entry.Tenant, entry.Value); err != nil {
			cfg.Logger.Error("kill-switch release failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}

		ev := audit.NewEvent(audit.DecisionAllow, "admin/kill-switch/release")
		ev.Check = audit.CheckCapability
		ev.Reason = "kill switch released (" + string(entry.Type) + ")"
		ev.AgentID = entry.Value
		ev.Tenant = entry.Tenant
		ev.RemoteIP = r.RemoteAddr
		ev.ElevationID = resolveElevationID(r)
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("kill switch released",
			"scope", entry.Type, "tenant", entry.Tenant, "agent", entry.Value, "by", auth.tenant)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
}

// NewAdminKillSwitchListHandler returns GET /v1/admin/kill-switch.
// Lists engaged kills. Superadmin sees all; a per-tenant admin sees
// only kills that apply to its own tenant.
func NewAdminKillSwitchListHandler(cfg AdminConfig) http.Handler {
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
		if cfg.KillSwitch == nil {
			adminError(w, http.StatusServiceUnavailable, "kill switch not configured")
			return
		}
		all, err := cfg.KillSwitch.List(r.Context())
		if err != nil {
			cfg.Logger.Error("kill-switch list failed", "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		// Per-tenant admins only see kills relevant to their tenant: the
		// global breaker (which affects them) and their own tenant/agent
		// kills. They must not see other tenants' entries.
		out := all
		if auth.tenant != "" {
			out = out[:0]
			for _, e := range all {
				if e.Type == killswitch.ScopeGlobal || e.Tenant == auth.tenant {
					out = append(out, e)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"kill_switch": out})
	})
}
