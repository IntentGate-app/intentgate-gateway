// Command decoy-responder is the isolated high-interaction decoy for the
// deception fabric. A honey-tool can be low-interaction (it trips the
// instant it is called and the call is blocked) or high-interaction: the
// call is routed here instead, to a sandboxed service that answers
// convincingly so a compromised agent keeps operating while its behaviour
// is captured. Every engagement is reported as a trip to the console.
//
// This runs as its own container, deliberately isolated from anything
// real: it holds no credentials, reaches no production system, and can
// only ever return canned data. That isolation is the point. If an agent
// is talking to this service at all, it is already a definitive
// compromise, so nothing it does here can cause harm.
//
// Configuration (all optional):
//
//	DECOY_RESPONDER_ADDR         listen address (default ":8090")
//	INTENTGATE_DECEPTION_TRIP_URL console trip-intake endpoint
//	INTENTGATE_DECEPTION_TOKEN    shared bearer token for reporting
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/deception"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// engageRequest is the shape a routed decoy call arrives in. Fields are
// best-effort: a real attacker will not fill them in politely, so we fall
// back to the request path and remote address.
type engageRequest struct {
	Tool  string         `json:"tool"`
	Agent string         `json:"agent"`
	Args  map[string]any `json:"args"`
}

// cannedResult returns a plausible-looking response for a decoy tool so
// the agent believes the call succeeded and keeps going. It never returns
// anything real.
func cannedResult(tool string) map[string]any {
	return map[string]any{
		"status":  "ok",
		"tool":    tool,
		"message": "completed",
		"id":      "req-" + time.Now().UTC().Format("20060102150405"),
	}
}

func main() {
	addr := getenv("DECOY_RESPONDER_ADDR", ":8090")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	reporter := deception.NewHTTPReporter(
		os.Getenv("INTENTGATE_DECEPTION_TRIP_URL"),
		os.Getenv("INTENTGATE_DECEPTION_ENGAGEMENT_URL"),
		os.Getenv("INTENTGATE_DECEPTION_TOKEN"),
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var body engageRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		tool := body.Tool
		if tool == "" {
			tool = r.URL.Path
		}
		agent := body.Agent
		if agent == "" {
			agent = "unattributed agent"
		}

		logger.Warn("decoy engaged",
			"tool", tool, "agent", agent, "remote", r.RemoteAddr)

		if reporter != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			reporter.Report(ctx, deception.Trip{
				DecoyName:   tool,
				Pillar:      "tool",
				Agent:       agent,
				Severity:    "critical",
				ActionTaken: "contained",
				Detail:      "high-interaction decoy engaged: " + tool,
			})
			cancel()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cannedResult(tool))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("decoy responder listening", "addr", addr,
		"version", version, "reporting", reporter != nil)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("decoy responder stopped", "err", err)
		os.Exit(1)
	}
}
