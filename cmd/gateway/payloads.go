package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/payloads"
)

// loadPayloadCapture constructs the response-capture store and policy.
//
// Returns (nil, zero policy) when capture is off, which is the default and the
// state every deployment starts in. A nil store disables capture in the
// handler regardless of what the policy says, so a half-configured gateway
// cannot believe it is recording responses when it is not.
//
// The return type is the INTERFACE, not *PostgresStore, and that is
// deliberate. Returning a typed nil pointer and assigning it to an interface
// field produces a non-nil interface holding a nil pointer: the handler's
// `Payloads != nil` guard would pass and the first capture would panic on a
// nil receiver. Returning payloads.Store means "off" is a genuinely nil
// interface.
//
// Env:
//
//	INTENTGATE_PAYLOAD_CAPTURE_ENABLED  "true" to turn it on
//	INTENTGATE_PAYLOAD_CAPTURE_TOOLS    comma-separated tool names or
//	                                    trailing-* patterns. "agent:*" captures
//	                                    agent-to-agent hand-offs only.
//	INTENTGATE_PAYLOAD_CAPTURE_TTL      retention, e.g. "336h". Default 14d.
//	INTENTGATE_PAYLOAD_CAPTURE_MAX_KB   per-body cap in KiB. Default 256.
func loadPayloadCapture(
	ctx context.Context,
	logger *slog.Logger,
	postgresURL string,
) (payloads.Store, payloads.Policy, error) {
	if envOr("INTENTGATE_PAYLOAD_CAPTURE_ENABLED", "") != "true" {
		return nil, payloads.Policy{}, nil
	}

	tools := splitCSV(envOr("INTENTGATE_PAYLOAD_CAPTURE_TOOLS", ""))
	if len(tools) == 0 {
		// Enabled with nothing selected would retain nothing while reporting
		// capture as on. Refuse, rather than let an operator believe they have
		// evidence they do not have.
		return nil, payloads.Policy{}, fmt.Errorf(
			"INTENTGATE_PAYLOAD_CAPTURE_ENABLED=true requires INTENTGATE_PAYLOAD_CAPTURE_TOOLS " +
				"(e.g. \"agent:*\" for agent-to-agent hand-offs only)")
	}
	if postgresURL == "" {
		// Same reasoning as audit persistence: capture without somewhere to
		// put it is a config error, not a degraded mode.
		return nil, payloads.Policy{}, fmt.Errorf(
			"INTENTGATE_PAYLOAD_CAPTURE_ENABLED=true requires INTENTGATE_POSTGRES_URL")
	}

	pol := payloads.Policy{Enabled: true, Tools: tools}
	if raw := envOr("INTENTGATE_PAYLOAD_CAPTURE_TTL", ""); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return nil, payloads.Policy{}, fmt.Errorf(
				"invalid INTENTGATE_PAYLOAD_CAPTURE_TTL %q: want a positive Go duration like 336h", raw)
		}
		pol.TTL = d
	}
	if raw := envOr("INTENTGATE_PAYLOAD_CAPTURE_MAX_KB", ""); raw != "" {
		kb, err := strconv.Atoi(raw)
		if err != nil || kb <= 0 {
			return nil, payloads.Policy{}, fmt.Errorf(
				"invalid INTENTGATE_PAYLOAD_CAPTURE_MAX_KB %q: want a positive integer", raw)
		}
		pol.MaxBytes = kb * 1024
	}
	pol = pol.Normalise()

	store, err := payloads.NewPostgresFromDSN(ctx, postgresURL)
	if err != nil {
		return nil, payloads.Policy{}, err
	}

	// Say plainly what is now being retained. Turning this on is a decision
	// with a compliance surface, and the startup log is where an operator
	// reviewing a running system will look for it.
	logger.Warn("response capture is ON: tool and agent-to-agent responses are being retained",
		"tools", strings.Join(pol.Tools, ","),
		"retention", pol.TTL.String(),
		"max_body_kb", pol.MaxBytes/1024,
		"stored", "redacted response only; the raw response is hashed, never stored",
		"note", "reading a captured payload is access to customer data and is separately audited")

	return store, pol, nil
}

// startPayloadPurge runs expiry deletion on a ticker.
//
// Expiry is already enforced in the read query, so a stalled purge cannot leak
// an expired payload to a reader. This exists to stop the table growing without
// bound, which is a storage problem rather than a privacy one.
func startPayloadPurge(ctx context.Context, logger *slog.Logger, store payloads.Store) {
	if store == nil {
		return
	}
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n, err := store.Purge(ctx, time.Now().UTC())
				if err != nil {
					logger.Warn("payload purge failed", "err", err)
					continue
				}
				if n > 0 {
					logger.Info("payload purge", "expired_rows_deleted", n)
				}
			}
		}
	}()
}
