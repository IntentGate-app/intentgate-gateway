package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Reporter pushes signed rollups OUTBOUND ONLY to the control-plane ingest
// endpoint over a single bearer-authenticated connection the node opens itself.
// The control plane never dials in; there is no inbound listener on the data
// plane for this path. Transport auth is the bearer token; tamper-evidence is
// the in-body HMAC signature (see Sign). Safe for concurrent use.
type Reporter struct {
	url    string
	token  string
	client *http.Client
}

// NewReporter returns a reporter that POSTs rollups to url with the given
// bearer token. A nil return (empty url or token) is a safe no-op, so callers
// can wire it unconditionally and leave federation disabled by config -- a
// gateway with no control plane configured simply never pushes.
func NewReporter(url, token string) *Reporter {
	if url == "" || token == "" {
		return nil
	}
	return &Reporter{
		url:    url,
		token:  token,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether this reporter will actually push. A nil receiver is
// disabled, so callers need not nil-check before deciding to build a rollup.
func (r *Reporter) Enabled() bool { return r != nil }

// Push sends one rollup and returns any delivery error so the caller's loop can
// log federation health. Unlike the deception trip reporter this returns the
// error rather than swallowing it, because a push loop wants to surface a
// control-plane outage -- but delivery failure never affects any local decision,
// which has already been made and audited by the time a rollup is built. A nil
// receiver is a safe no-op returning nil.
func (r *Reporter) Push(ctx context.Context, rollup Rollup) error {
	if r == nil {
		return nil
	}
	body, err := json.Marshal(rollup)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read a small bounded slice of the body for diagnostics only.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("control plane rejected rollup: status %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}
	return nil
}
