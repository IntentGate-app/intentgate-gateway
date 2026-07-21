package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
	"github.com/IntentGate-app/intentgate-gateway/internal/payloads"
)

// capturePayload retains what the agent actually received, when the deployment
// has asked for it, and returns the audit annotations describing what happened.
//
// Ordering matters and is the whole point:
//
//   - the RAW upstream envelope is hashed, so the record anchors to what the
//     upstream really returned;
//   - the POST-FILTER envelope is stored, because that is what the agent saw
//     and because the alternative is unredacted customer data at rest.
//
// It never fails the call. A capture problem is an observability problem; a
// tool call that succeeded must not be reported to the agent as failed because
// the gateway could not write an audit convenience. Errors are logged and the
// call proceeds, with result_stored left false so the console can be honest
// about the payload being unavailable.
func (h *mcpHandler) capturePayload(
	ctx context.Context,
	eventID string,
	cap capabilityCheckResult,
	toolName string,
	rawUpstream []byte,
	delivered any,
) auditEmitOption {
	pol := h.cfg.PayloadPolicy
	if !pol.ShouldCapture(toolName) || len(rawUpstream) == 0 {
		return func(*audit.Event) {}
	}
	pol = pol.Normalise()

	// Hash first, and hash the raw form. Doing this before anything else means
	// a later failure to store still leaves a usable integrity anchor on the
	// event.
	rawHash := payloads.HashRaw(rawUpstream)
	rawLen := len(rawUpstream)

	stored := false
	if h.cfg.Payloads != nil {
		body, err := json.Marshal(delivered)
		if err != nil {
			// The envelope we are about to send the agent will not re-marshal.
			// That is strange enough to log, but it is not the call's problem.
			if h.cfg.Logger != nil {
				h.cfg.Logger.Warn("payload capture: cannot marshal delivered response",
					"tool", toolName, "err", err)
			}
		} else {
			body, truncated := pol.Truncate(body)
			redacted := truncated || len(body) != rawLen ||
				string(body) != string(rawUpstream)

			var tenant string
			if cap.token != nil {
				tenant = cap.token.Tenant
			}
			rec := payloads.Record{
				EventID:    eventID,
				Tenant:     tenant,
				AgentID:    cap.agentID,
				Tool:       toolName,
				RawSHA256:  rawHash,
				RawBytes:   rawLen,
				Body:       body,
				Redacted:   redacted,
				CapturedAt: time.Now().UTC(),
				ExpiresAt:  time.Now().UTC().Add(pol.TTL),
			}
			if err := h.cfg.Payloads.Put(ctx, rec); err != nil {
				if h.cfg.Logger != nil {
					h.cfg.Logger.Warn("payload capture: store failed",
						"tool", toolName, "event_id", eventID, "err", err)
				}
			} else {
				stored = true
			}
		}
	}

	return func(e *audit.Event) {
		e.ResultSHA256 = rawHash
		e.ResultBytes = rawLen
		e.ResultStored = stored
	}
}

// withEventID stamps the gateway-generated id used to join this decision to
// its captured response.
func withEventID(id string) auditEmitOption {
	return func(e *audit.Event) {
		if id != "" {
			e.EventID = id
		}
	}
}
