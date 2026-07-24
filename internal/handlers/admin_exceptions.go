package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/capability"
)

// defaultExceptionMaxTTL caps how long a risk-exception-minted token may
// live when the operator hasn't set AdminConfig.ExceptionMaxTTL. A policy
// exception is, by definition, temporary; 48h is a deliberately short
// ceiling so an approval workflow can never grant an effectively permanent
// widening.
const defaultExceptionMaxTTL = 48 * time.Hour

// NewAdminExceptionGrantHandler handles POST /v1/admin/exceptions/grant —
// the inbound side of the risk-register / IGA loop (Workflow C).
//
// When a temporary policy exception is APPROVED in ServiceNow IRM (or any
// GRC/IGA workflow) — e.g. "let agent-finance-1 run high-value wire
// transfers for the next 24h" — the approval fires an outbound call, via
// the customer's in-VPC MID Server, to this endpoint. IntentGate then mints
// a genuine, HMAC-chained capability token that is:
//
//   - locked to the named agent (automatic agent-lock caveat),
//   - scoped to only the approved tool(s) (tool-whitelist caveat),
//   - hard-expiring at ttl_seconds, capped at ExceptionMaxTTL, and
//   - audited as an Allow event carrying the ServiceNow exception ref and
//     the approver, so the grant is tamper-evidently attributable.
//
// This reuses the exact same capability.Mint path as /v1/admin/mint — there
// is no parallel or weaker token type. The endpoint is guarded by the admin
// token (the MID Server holds it as a credential and never exposes it to
// the ServiceNow cloud), so an external approval alone cannot widen scope
// without the operator's admin secret.
func NewAdminExceptionGrantHandler(cfg AdminConfig) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Audit == nil {
		cfg.Audit = audit.NewNullEmitter()
	}
	maxTTL := cfg.ExceptionMaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultExceptionMaxTTL
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		auth := resolveAdminAuth(r, cfg)
		if !auth.ok {
			adminError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		if len(cfg.MasterKey) == 0 {
			adminError(w, http.StatusServiceUnavailable, "master key not configured: exception grant disabled")
			return
		}

		var body struct {
			AgentID      string   `json:"agent_id"`
			Tenant       string   `json:"tenant"`
			Zone         string   `json:"zone"`
			Tools        []string `json:"tools"`
			TTLSeconds   int64    `json:"ttl_seconds"`
			ExceptionRef string   `json:"exception_ref"`
			ApprovedBy   string   `json:"approved_by"`
			Reason       string   `json:"reason"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			adminError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}

		agent := strings.TrimSpace(body.AgentID)
		if agent == "" {
			adminError(w, http.StatusBadRequest, "agent_id is required")
			return
		}
		ref := strings.TrimSpace(body.ExceptionRef)
		if ref == "" {
			// An exception grant must be attributable to an approved
			// record; a token minted with no reference would be an
			// un-auditable back door.
			adminError(w, http.StatusBadRequest, "exception_ref is required (the approved GRC/IGA exception id)")
			return
		}
		// A temporary exception must expire, and must be scoped. Refuse an
		// unbounded or un-scoped grant outright — those are the two ways an
		// exception could silently become a standing privilege.
		if body.TTLSeconds <= 0 {
			adminError(w, http.StatusBadRequest, "ttl_seconds must be > 0 (an exception must expire)")
			return
		}
		if int64(maxTTL/time.Second) < body.TTLSeconds {
			adminError(w, http.StatusBadRequest, "ttl_seconds exceeds the maximum exception window")
			return
		}
		var tools []string
		for _, t := range body.Tools {
			if t = strings.TrimSpace(t); t != "" {
				tools = append(tools, t)
			}
		}
		if len(tools) == 0 {
			adminError(w, http.StatusBadRequest, "tools must list at least one tool (an exception must be scoped)")
			return
		}

		// Tenant resolution mirrors /v1/admin/mint: a per-tenant admin's
		// tenant wins and a mismatching body is rejected, so a scoped token
		// cannot mint cross-tenant.
		tenant := strings.TrimSpace(body.Tenant)
		if auth.tenant != "" {
			if tenant != "" && tenant != auth.tenant {
				adminError(w, http.StatusForbidden, "tenant in body does not match admin token's tenant")
				return
			}
			tenant = auth.tenant
		}

		expiry := time.Now().UTC().Add(time.Duration(body.TTLSeconds) * time.Second)
		opts := capability.MintOptions{
			Tenant:  tenant,
			Zone:    strings.TrimSpace(body.Zone),
			Subject: agent,
			Expiry:  expiry,
			Caveats: []capability.Caveat{{
				Type:  capability.CaveatToolWhitelist,
				Tools: tools,
			}},
		}
		tok, err := capability.Mint(cfg.MasterKey, opts)
		if err != nil {
			cfg.Logger.Error("exception grant mint failed", "agent", agent, "err", err)
			adminError(w, http.StatusBadRequest, "mint error: "+err.Error())
			return
		}
		encoded, err := tok.Encode()
		if err != nil {
			cfg.Logger.Error("exception grant encode failed", "agent", agent, "err", err)
			adminError(w, http.StatusInternalServerError, "encode error")
			return
		}

		// Tamper-evident record: who approved which exception, for which
		// agent + tools, and the jti so the grant can be revoked early.
		reason := "risk exception " + ref + " granted for agent=" + agent + " tools=" + strings.Join(tools, ",")
		if by := strings.TrimSpace(body.ApprovedBy); by != "" {
			reason += " approved_by=" + by
		}
		if extra := strings.TrimSpace(body.Reason); extra != "" {
			reason += " (" + extra + ")"
		}
		ev := audit.NewEvent(audit.DecisionAllow, "admin/exception-grant")
		ev.Check = audit.CheckCapability
		ev.Reason = reason
		ev.CapabilityTokenID = tok.ID
		ev.RootCapabilityTokenID = tok.RootID
		ev.CaveatCount = tok.CaveatCount()
		ev.Tenant = tok.Tenant
		ev.AgentID = agent
		ev.RemoteIP = r.RemoteAddr
		ev.ElevationID = resolveElevationID(r)
		cfg.Audit.Emit(r.Context(), ev)

		cfg.Logger.Info("risk exception granted",
			"exception_ref", ref, "agent", agent, "tools", len(tools),
			"ttl_seconds", body.TTLSeconds, "jti", tok.ID)

		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":         encoded,
			"jti":           tok.ID,
			"agent_id":      agent,
			"tools":         tools,
			"exception_ref": ref,
			"expires_at":    expiry.Format(time.RFC3339),
		})
	})
}
