package bundle

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AckStatus is the outcome a gateway reports after trying to apply a bundle.
type AckStatus string

const (
	AckApplied  AckStatus = "applied"  // verified + swapped
	AckRejected AckStatus = "rejected" // failed signature/verification
	AckError    AckStatus = "error"    // transport/decode failure
)

// BundleAck is the lightweight receipt a gateway posts after each apply attempt,
// so the control plane (Command Center) can show policy-propagation coverage.
type BundleAck struct {
	Node      string    `json:"node"`
	Subject   string    `json:"subject"`
	BundleID  string    `json:"bundle_id"`
	Version   string    `json:"version"`
	AppliedAt time.Time `json:"applied_at"`
	Status    AckStatus `json:"status"`
	Detail    string    `json:"detail,omitempty"`
}

// Subscriber is the gateway-side transport: it pulls compiled bundles from the
// control plane and installs them into the local BundleRegistry. On start it
// fetches the baseline (cold start / after a partition), then watches an SSE
// stream for real-time pushes, acking every apply attempt. It reconnects with
// exponential backoff so a dropped stream never leaves a node stale silently.
type Subscriber struct {
	BaseURL    string // control-plane base, e.g. https://control.intentgate.app
	Node       string // this gateway node id
	AuthHeader string // added to every request, e.g. "Bearer <node-token>"
	Client     *http.Client
	reg        *BundleRegistry
}

// NewSubscriber wires a subscriber to a registry. The client has no overall
// timeout because the watch stream is long-lived; per-request deadlines come
// from the context instead.
func NewSubscriber(baseURL, node string, reg *BundleRegistry) *Subscriber {
	return &Subscriber{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Node:    node,
		Client:  &http.Client{},
		reg:     reg,
	}
}

func (s *Subscriber) auth(req *http.Request) {
	if s.AuthHeader != "" {
		req.Header.Set("Authorization", s.AuthHeader)
	}
}

// Run drives the transport until ctx is cancelled: baseline fetch, then watch,
// reconnecting with backoff on any disconnect.
func (s *Subscriber) Run(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for ctx.Err() == nil {
		if err := s.FetchBaseline(ctx); err != nil && ctx.Err() == nil {
			// Non-fatal: proceed to watch; a push will still deliver updates.
			_ = err
		}
		err := s.Watch(ctx)
		if ctx.Err() != nil {
			return
		}
		_ = err // disconnected; back off and reconnect
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// FetchBaseline pulls every active bundle for this node and installs them.
func (s *Subscriber) FetchBaseline(ctx context.Context) error {
	u := s.BaseURL + "/api/v1/bundles/active?node=" + url.QueryEscape(s.Node)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	s.auth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("baseline fetch: %s", resp.Status)
	}
	var bundles []*CompiledGateBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundles); err != nil {
		return err
	}
	for _, b := range bundles {
		s.apply(ctx, b)
	}
	return nil
}

// FetchActive pulls the single active bundle for one subject (partition recovery).
func (s *Subscriber) FetchActive(ctx context.Context, subject string) (*CompiledGateBundle, error) {
	u := s.BaseURL + "/api/v1/bundles/active?node=" + url.QueryEscape(s.Node) + "&subject=" + url.QueryEscape(subject)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	s.auth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch active %s: %s", subject, resp.Status)
	}
	var b CompiledGateBundle
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Watch subscribes to the SSE push stream and applies each bundle update. It
// returns when the stream closes or ctx is cancelled; Run handles reconnect.
func (s *Subscriber) Watch(ctx context.Context) error {
	u := s.BaseURL + "/api/v1/bundles/watch?node=" + url.QueryEscape(s.Node)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	s.auth(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("watch: %s", resp.Status)
	}

	sc := bufio.NewScanner(resp.Body)
	// Bundles can be large; give the scanner room (default is 64KB).
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if line == "" { // event boundary
			if data.Len() > 0 {
				var b CompiledGateBundle
				if err := json.Unmarshal([]byte(data.String()), &b); err == nil {
					s.apply(ctx, &b)
				}
				data.Reset()
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	return sc.Err()
}

// apply verifies + swaps the bundle and acks the outcome.
func (s *Subscriber) apply(ctx context.Context, b *CompiledGateBundle) {
	status := AckApplied
	detail := ""
	if err := s.reg.LoadAndSwap(b); err != nil {
		status = AckRejected
		detail = err.Error()
	}
	s.ack(ctx, b, status, detail)
}

func (s *Subscriber) ack(ctx context.Context, b *CompiledGateBundle, status AckStatus, detail string) {
	ack := BundleAck{
		Node:      s.Node,
		Subject:   b.StaticCapabilities.Subject,
		BundleID:  b.BundleID,
		Version:   b.Version,
		AppliedAt: time.Now().UTC(),
		Status:    status,
		Detail:    detail,
	}
	body, err := json.Marshal(ack)
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.BaseURL+"/api/v1/bundles/ack", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	s.auth(req)
	if resp, err := s.Client.Do(req); err == nil {
		resp.Body.Close()
	}
}
