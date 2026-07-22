package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Per-tool upstream credential brokering admin API.
//
// These endpoints let the console manage the secret each tool server
// requires. The gateway holds the credentials (encrypted at rest) and
// injects them on forwarded calls, so agents never possess any tool
// secret. Secret values are write-only: the list endpoint returns the
// tool and header NAME only, never the value.

// NewAdminCredentialsListHandler returns GET /v1/admin/upstream-credentials.
// Body: {"credentials":[{"tool":"...","header":"Authorization"}, ...]}.
func NewAdminCredentialsListHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if auth := resolveAdminAuth(r, cfg); !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Credentials == nil {
			adminError(w, http.StatusServiceUnavailable, "per-tool credentials not configured")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentials": cfg.Credentials.List(),
		})
	})
}

// NewAdminCredentialsSetHandler returns POST /v1/admin/upstream-credentials.
// Body: {"tool":"transfer_funds","credential":"Authorization: Bearer sk-..."}.
// A new credential for an existing tool rotates it live.
func NewAdminCredentialsSetHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if auth := resolveAdminAuth(r, cfg); !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Credentials == nil {
			adminError(w, http.StatusServiceUnavailable, "per-tool credentials not configured")
			return
		}

		var body struct {
			Tool       string `json:"tool"`
			Credential string `json:"credential"`
			// Optional governance metadata. Owner is the accountable
			// human/team for the secret; ExpiresAt (RFC3339) is when it
			// should be rotated by. Both are advisory and never the secret.
			Owner     string `json:"owner"`
			ExpiresAt string `json:"expires_at"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
		if strings.TrimSpace(body.Tool) == "" {
			adminError(w, http.StatusBadRequest, "tool is required")
			return
		}
		var expiresAt time.Time
		if s := strings.TrimSpace(body.ExpiresAt); s != "" {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				adminError(w, http.StatusBadRequest, "expires_at must be RFC3339: "+err.Error())
				return
			}
			expiresAt = t
		}
		if err := cfg.Credentials.SetMeta(r.Context(), body.Tool, body.Credential, body.Owner, expiresAt); err != nil {
			// Most failures are a malformed credential ("Header: value");
			// surface the message as a 400. The secret itself is never logged.
			cfg.Logger.Warn("set upstream credential failed", "tool", body.Tool, "err", err)
			adminError(w, http.StatusBadRequest, err.Error())
			return
		}
		cfg.Logger.Info("upstream credential set", "tool", strings.TrimSpace(body.Tool))
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
}

// NewAdminCredentialsDeleteHandler returns
// DELETE /v1/admin/upstream-credentials/{tool}. The tool then falls back
// to the global upstream credential.
func NewAdminCredentialsDeleteHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if auth := resolveAdminAuth(r, cfg); !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if cfg.Credentials == nil {
			adminError(w, http.StatusServiceUnavailable, "per-tool credentials not configured")
			return
		}
		tool := strings.TrimSpace(r.PathValue("tool"))
		if tool == "" {
			adminError(w, http.StatusBadRequest, "tool is required")
			return
		}
		if err := cfg.Credentials.Remove(r.Context(), tool); err != nil {
			cfg.Logger.Error("delete upstream credential failed", "tool", tool, "err", err)
			adminError(w, http.StatusServiceUnavailable, "store error: "+err.Error())
			return
		}
		cfg.Logger.Info("upstream credential deleted", "tool", tool)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
}
