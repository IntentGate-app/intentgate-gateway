package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/intentauthz"
	"github.com/IntentGate-app/intentgate-gateway/internal/mcp"
	"github.com/IntentGate-app/intentgate-gateway/internal/upstream"
)

// DefaultAgentHeader is where the dedicated new-authority path reads the caller's
// agent identity from. It is intentionally NOT the legacy capability token — this
// path is governed solely by the BA-/IG- chain, so it takes identity from a plain
// header and resolves it to a canonical EUID in the control plane.
const DefaultAgentHeader = "X-IntentGate-Agent"

// HeaderDecisionID echoes the control-plane decision id on the response so the
// proof (DEC-) is retrievable without parsing the JSON-RPC body.
const HeaderDecisionID = "X-IntentGate-Decision"

// IntentGrantMCPConfig configures the dedicated new-authority MCP enforcement path
// (POST /v1/mcp/ig). This path is deliberately separate from /v1/mcp: the legacy
// capability/bundle pipeline is untouched, and here the governed BA-/IG- decision
// is the SOLE authority. Every consequential call (tools/call) is authorized by
// the control plane before it is forwarded to the toolserver.
type IntentGrantMCPConfig struct {
	// Logger is required (defaults to slog.Default()).
	Logger *slog.Logger
	// Authz is the control-plane decision client. Required — without it the path
	// cannot make a governed decision and must not be mounted.
	Authz *intentauthz.Client
	// Upstream is the downstream MCP toolserver. Required for this path: an ALLOW
	// must be able to execute, and a DENY must be provably able to reach it but not.
	Upstream *upstream.Client
	// AgentHeader overrides the header the agent identity is read from.
	AgentHeader string
	// AuthorizeTimeout bounds the control-plane call; zero uses the client default.
	AuthorizeTimeout time.Duration
}

// NewIntentGrantMCPHandler returns POST /v1/mcp/ig.
//
// Pipeline (tools/call): read agent id (header) + tool name (params.name) → ask the
// control plane → ALLOW forwards the exact JSON-RPC body to the toolserver and returns
// its result; DENY returns a JSON-RPC error and DOES NOT forward. A control plane that
// cannot be reached fails CLOSED — the toolserver is never called. Discovery/handshake
// methods (initialize, tools/list, ping) pass through to the toolserver unauthorized,
// since they are not consequential actions.
func NewIntentGrantMCPHandler(cfg IntentGrantMCPConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.AgentHeader == "" {
		cfg.AgentHeader = DefaultAgentHeader
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeRPC(w, mcp.NewErrorResponse(nil, mcp.CodeParseError, "could not read request body", nil))
			return
		}
		var req mcp.Request
		if err := json.Unmarshal(raw, &req); err != nil {
			writeRPC(w, mcp.NewErrorResponse(nil, mcp.CodeParseError, "invalid JSON-RPC request", nil))
			return
		}

		// Non-consequential methods pass through to the toolserver (or a local stub
		// when no upstream is wired). No authorization: discovery is not an action.
		if req.Method != mcp.MethodToolsCall {
			igForward(w, cfg, r.Context(), req, raw, "")
			return
		}

		// --- Consequential: tools/call is authorized before anything executes. ---
		agentRef := r.Header.Get(cfg.AgentHeader)
		if agentRef == "" {
			writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
				"missing agent identity",
				map[string]any{"reason": "MISSING_AGENT_IDENTITY", "header": cfg.AgentHeader}))
			return
		}
		var params struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params, &params)
		if params.Name == "" {
			writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodeInvalidParams,
				"missing tool name", map[string]any{"reason": "MISSING_TOOL"}))
			return
		}

		azCtx := r.Context()
		if cfg.AuthorizeTimeout > 0 {
			var cancel context.CancelFunc
			azCtx, cancel = context.WithTimeout(azCtx, cfg.AuthorizeTimeout)
			defer cancel()
		}

		decision, err := cfg.Authz.Authorize(azCtx, intentauthz.Request{
			AgentRef: agentRef,
			ToolRef:  params.Name,
			Method:   req.Method,
			Context:  map[string]any{"channel": "mcp", "remote_ip": r.RemoteAddr},
		})
		if err != nil {
			// FAIL CLOSED. The control plane could not be reached or gave an
			// unusable answer — the action must NOT proceed to the toolserver.
			cfg.Logger.Error("intentgrant authorize unavailable; failing closed",
				"tool", params.Name, "agent", agentRef, "err", err.Error())
			writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodeInternalError,
				"authorization unavailable — failing closed",
				map[string]any{"reason": "AUTHORIZATION_UNAVAILABLE", "fail_closed": true}))
			return
		}

		if decision.Record.DecisionID != "" {
			w.Header().Set(HeaderDecisionID, decision.Record.DecisionID)
		}

		if !decision.Allowed() {
			// Governed DENY. The toolserver is never contacted.
			cfg.Logger.Warn("intentgrant DENY (blocked before execution)",
				"tool", params.Name, "agent", agentRef,
				"reason", decision.Record.ReasonCode, "decision", decision.Record.DecisionID)
			writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodePolicyFailed,
				"authorization denied",
				map[string]any{
					"authority":   "intentgrant",
					"reason":      decision.Record.ReasonCode,
					"decision_id": decision.Record.DecisionID,
				}))
			return
		}

		// ALLOW — only now does the call reach the toolserver.
		cfg.Logger.Info("intentgrant ALLOW (forwarding to toolserver)",
			"tool", params.Name, "agent", agentRef,
			"grant", strOrEmpty(decision.Record.GrantID), "decision", decision.Record.DecisionID)
		igForward(w, cfg, r.Context(), req, raw, decision.Record.DecisionID)
	})
}

// igForward forwards the exact JSON-RPC body to the toolserver and writes the raw
// response back. When no upstream is configured the call cannot execute, which for
// this path is an upstream-unavailable error (never a silent success).
func igForward(w http.ResponseWriter, cfg IntentGrantMCPConfig, ctx context.Context, req mcp.Request, raw []byte, decisionID string) {
	if cfg.Upstream == nil {
		writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodeUpstreamUnavailable,
			"no upstream toolserver configured", map[string]any{"reason": "NO_UPSTREAM"}))
		return
	}
	resp, err := cfg.Upstream.Forward(ctx, raw, nil)
	if err != nil {
		var status int
		if uerr, ok := err.(*upstream.Error); ok {
			status = uerr.Status
		}
		cfg.Logger.Error("intentgrant upstream forward failed", "err", err.Error(), "upstream_status", status)
		writeRPC(w, mcp.NewErrorResponse(req.ID, mcp.CodeUpstreamUnavailable,
			"upstream toolserver error", map[string]any{"upstream_status": status}))
		return
	}
	if decisionID != "" {
		w.Header().Set(HeaderDecisionID, decisionID)
	}
	// Pass the toolserver's JSON-RPC response through unchanged.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp.Body)
}

func writeRPC(w http.ResponseWriter, resp *mcp.Response) {
	w.WriteHeader(http.StatusOK) // JSON-RPC carries errors in the body, not the HTTP status
	_ = json.NewEncoder(w).Encode(resp)
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
