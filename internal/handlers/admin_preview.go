package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/effectpreview"
)

// NewAdminEffectPreviewHandler returns the POST /v1/admin/preview handler.
//
// Request body:
//
//	{
//	  "tool": "delete_invoices",          // required
//	  "args": {"where": "status=void"}    // optional
//	}
//
// It computes a read-only Effect Preview of the candidate call, showing its
// blast radius (operation, scope, magnitude, destination, reversibility, and a
// plain-language summary) before the action is allowed to run. It never
// executes the call.
//
// Returns 400 on missing/invalid body, 401 on bad token.
func NewAdminEffectPreviewHandler(cfg AdminConfig) http.Handler {
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

		var body struct {
			Tool string         `json:"tool"`
			Args map[string]any `json:"args"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
			return
		}
		if strings.TrimSpace(body.Tool) == "" {
			adminError(w, http.StatusBadRequest, "missing required field \"tool\"")
			return
		}

		preview := effectpreview.Compute(body.Tool, body.Args, nil)
		_ = json.NewEncoder(w).Encode(preview)
	})
}
