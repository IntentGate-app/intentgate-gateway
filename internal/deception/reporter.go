package deception

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Reporter mirrors a trip to an external sink (the console's Monitor) so a
// live decoy touch shows up next to the ones an operator simulates. The
// gateway already records every trip in its own tamper-evident audit and
// SIEM stream; this is the additional, best-effort push to the console.
type Reporter interface {
	// Report sends one trip. Implementations must not block the request
	// path meaningfully and must swallow their own errors: a reporting
	// outage must never change the containment decision, which has
	// already happened by the time this is called.
	Report(ctx context.Context, t Trip)
}

// Trip is the payload posted to the console trip-intake endpoint. Field
// names match the console's POST /api/deception/trip body.
type Trip struct {
	DecoyID     string `json:"decoyId"`
	DecoyName   string `json:"decoyName"`
	Pillar      string `json:"pillar"`
	Agent       string `json:"agent"`
	Severity    string `json:"severity"`
	ActionTaken string `json:"actionTaken"`
	Detail      string `json:"detail"`
}

// HTTPReporter posts trips to the console trip-intake endpoint with a
// shared bearer token. Safe for concurrent use.
type HTTPReporter struct {
	url    string
	token  string
	client *http.Client
}

// NewHTTPReporter returns a reporter that POSTs to url with the given
// bearer token. A nil return (empty url or token) is a no-op reporter, so
// callers can wire it unconditionally and leave it disabled by config.
func NewHTTPReporter(url, token string) *HTTPReporter {
	if url == "" || token == "" {
		return nil
	}
	return &HTTPReporter{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// Report implements Reporter. Best-effort: any error is swallowed. A nil
// receiver is a safe no-op so callers need not nil-check.
func (r *HTTPReporter) Report(ctx context.Context, t Trip) {
	if r == nil {
		return
	}
	body, err := json.Marshal(t)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
