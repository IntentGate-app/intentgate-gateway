package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/capability"
	"github.com/IntentGate-app/intentgate-gateway/internal/killswitch"
	"github.com/IntentGate-app/intentgate-gateway/internal/pii"
	"github.com/IntentGate-app/intentgate-gateway/internal/revocation"
)

// ReplyHandlerConfig configures POST /v1/reply — the reply-side
// outbound gateway (A1).
//
// # What it is
//
// Where /v1/mcp governs what an agent DOES (its tool calls), /v1/reply
// governs what an agent RETURNS to the user. The agent, or the
// orchestrator that runs it, submits the proposed final answer here
// before delivering it. The gateway runs the same content engine that
// already guards tool responses — PII plus credential/secret detection —
// and returns one of three outcomes: allow the reply unchanged, return a
// redacted reply, or block it. A counts-only audit row records the
// decision so the full round trip (what the agent did AND what it
// returned) is on the tamper-evident record. The reply text and any
// matched values are never persisted.
//
// # Why it is deterministic
//
// This endpoint enforces data controls (does the reply disclose PII, a
// secret, or another declared class), not a judgement of whether the
// answer is correct. It reuses the same detector, action vocabulary, and
// counts-only audit discipline as the response-side filter, so the
// reply path and the tool-response path share one rule set.
type ReplyHandlerConfig struct {
	// Logger is required (defaults to slog.Default()).
	Logger *slog.Logger
	// MasterKey verifies the capability token. May be nil only when
	// RequireCapability is false (dev).
	MasterKey []byte
	// RequireCapability rejects replies that do not carry a valid
	// capability token.
	RequireCapability bool
	// ReplyFilter is the content filter applied to the reply. Reuse the
	// same *pii.Filter that guards tool responses so one rule set covers
	// both directions. nil disables inspection (replies pass through).
	ReplyFilter *pii.Filter
	// KillSwitch halts replies too: an engaged breaker for this agent,
	// tenant, or globally blocks the reply. A store error fails closed.
	KillSwitch killswitch.Store
	// Revocation blocks replies from a revoked token. A store error
	// fails closed.
	Revocation revocation.Store
	// Audit records the round-trip decision (counts only).
	Audit audit.Emitter
}

type replyRequest struct {
	Reply string `json:"reply"`
}

type replyResponse struct {
	Action  string            `json:"action"` // allow | redact | block
	Reply   string            `json:"reply"`  // possibly redacted; empty on block
	Counts  map[pii.Class]int `json:"counts,omitempty"`
	Classes []pii.Class       `json:"classes,omitempty"`
}

// NewReplyHandler returns the POST /v1/reply handler.
func NewReplyHandler(cfg ReplyHandlerConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// --- Identify the agent from its capability token ---
		var tenant, agentID string
		encoded, err := capability.FromAuthorizationHeader(r.Header.Get("Authorization"))
		if err != nil {
			replyError(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}
		if encoded == "" {
			if cfg.RequireCapability {
				replyError(w, http.StatusUnauthorized, "capability token required")
				return
			}
		} else {
			tok, derr := capability.Decode(encoded)
			if derr != nil {
				replyError(w, http.StatusUnauthorized, "invalid capability token")
				return
			}
			if verr := tok.Verify(cfg.MasterKey); verr != nil {
				replyError(w, http.StatusUnauthorized, "capability token verification failed")
				return
			}
			tenant, agentID = tok.Tenant, tok.Subject

			if cfg.Revocation != nil {
				revoked, rerr := cfg.Revocation.IsRevoked(r.Context(), tok.ID, tok.Tenant)
				if rerr != nil || revoked {
					replyBlocked(w, cfg, r, tenant, agentID, "token revoked or revocation store unavailable")
					return
				}
			}
		}

		// --- Kill switch (fail closed) ---
		if cfg.KillSwitch != nil {
			halted, _, kerr := cfg.KillSwitch.Active(r.Context(), tenant, agentID)
			if kerr != nil || halted {
				replyBlocked(w, cfg, r, tenant, agentID, "halted by kill switch")
				return
			}
		}

		// --- Parse body ---
		var body replyRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if derr := dec.Decode(&body); derr != nil {
			replyError(w, http.StatusBadRequest, "invalid JSON: "+derr.Error())
			return
		}

		// --- Content inspection ---
		if cfg.ReplyFilter == nil {
			_ = json.NewEncoder(w).Encode(replyResponse{Action: "allow", Reply: body.Reply})
			return
		}
		decision := cfg.ReplyFilter.ApplyToString(body.Reply)

		switch decision.Action {
		case pii.ActionBlock, pii.ActionEscalate:
			emitReplyAudit(cfg, r, audit.DecisionBlock, tenant, agentID,
				"reply blocked (classes="+classesString(decision.MatchedClasses)+")")
			cfg.Logger.Warn("reply blocked by outbound filter",
				"tenant", tenant, "agent", agentID, "classes", decision.MatchedClasses)
			_ = json.NewEncoder(w).Encode(replyResponse{
				Action:  "block",
				Reply:   "",
				Counts:  decision.Counts,
				Classes: decision.MatchedClasses,
			})
		case pii.ActionRedact:
			emitReplyAudit(cfg, r, audit.DecisionAllow, tenant, agentID,
				"reply redacted (classes="+classesString(decision.MatchedClasses)+")")
			_ = json.NewEncoder(w).Encode(replyResponse{
				Action:  "redact",
				Reply:   decision.Output,
				Counts:  decision.Counts,
				Classes: decision.MatchedClasses,
			})
		default: // ActionAllow
			// No audit row on a clean allow — same noise discipline as the
			// response-side PII filter.
			_ = json.NewEncoder(w).Encode(replyResponse{Action: "allow", Reply: body.Reply})
		}
	})
}

func replyError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// replyBlocked emits a block audit row and returns a 200 block outcome.
// A blocked reply is an inspection result, not an HTTP error: the caller
// gets action="block" with an empty reply and must not deliver it.
func replyBlocked(w http.ResponseWriter, cfg ReplyHandlerConfig, r *http.Request, tenant, agentID, reason string) {
	emitReplyAudit(cfg, r, audit.DecisionBlock, tenant, agentID, reason)
	_ = json.NewEncoder(w).Encode(replyResponse{Action: "block", Reply: ""})
}

func emitReplyAudit(cfg ReplyHandlerConfig, r *http.Request, d audit.Decision, tenant, agentID, reason string) {
	if cfg.Audit == nil {
		return
	}
	ev := audit.NewEvent(d, "reply")
	ev.Check = audit.CheckPII
	ev.AgentID = agentID
	ev.Tenant = tenant
	ev.Reason = reason
	ev.RemoteIP = r.RemoteAddr
	cfg.Audit.Emit(r.Context(), ev)
}

func classesString(cs []pii.Class) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = string(c)
	}
	return strings.Join(parts, ",")
}
