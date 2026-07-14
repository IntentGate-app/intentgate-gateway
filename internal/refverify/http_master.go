// http_master.go adds a live system-of-record connector for reference
// verification. HTTPVendorMaster implements the VendorMaster seam against a
// real HTTP endpoint (for example an SAP Gateway OData service exposing the
// vendor / business-partner master, or any REST HR/CRM system of record),
// replacing the embedded StaticVendorMaster allowlist with an authenticated
// live lookup.
//
// Failure is fail-closed by contract: any transport error, timeout, or
// non-success status returns a non-nil error, which the Verifier turns into a
// quarantine (never pay a payee we could not verify). A definitive "not found"
// (HTTP 404, or a 200 whose body marks the payee absent) returns
// (Record{}, false, nil), which the Verifier treats as payee-not-in-master.
//
// A short-TTL in-memory cache absorbs repeat lookups without hammering the
// system of record. Safe for concurrent use.
package refverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTPConfig configures an HTTPVendorMaster.
type HTTPConfig struct {
	// Endpoint is the system-of-record URL. If it contains the literal
	// "{payee}", the normalized payee key is substituted there (path or query
	// position); otherwise the payee is appended as the Param query parameter.
	Endpoint string
	// Param is the query-parameter name used to pass the payee when Endpoint
	// has no {payee} placeholder. Defaults to "payee".
	Param string
	// Headers are sent on every request (auth token, API key, etc.), e.g.
	// {"Authorization": "Bearer ..."}.
	Headers map[string]string
	// Timeout bounds each lookup. Defaults to 5s.
	Timeout time.Duration
	// CacheTTL is how long a lookup result is cached. 0 disables caching.
	CacheTTL time.Duration
}

// HTTPVendorMaster is a live VendorMaster backed by a system-of-record HTTP
// endpoint.
type HTTPVendorMaster struct {
	client   *http.Client
	endpoint string
	param    string
	headers  map[string]string
	ttl      time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	rec   Record
	found bool
	exp   time.Time
}

// NewHTTPVendorMaster builds an HTTPVendorMaster from cfg.
func NewHTTPVendorMaster(cfg HTTPConfig) *HTTPVendorMaster {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	param := cfg.Param
	if param == "" {
		param = "payee"
	}
	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = v
	}
	return &HTTPVendorMaster{
		client:   &http.Client{Timeout: timeout},
		endpoint: cfg.Endpoint,
		param:    param,
		headers:  headers,
		ttl:      cfg.CacheTTL,
		cache:    make(map[string]cacheEntry),
	}
}

// sorResponse is the tolerated response shape from the system of record. The
// optional "found" flag lets a 200 response express a definitive absence.
type sorResponse struct {
	Payee string `json:"payee"`
	Name  string `json:"name"`
	Found *bool  `json:"found"`
}

// Lookup implements VendorMaster against the live system of record.
func (h *HTTPVendorMaster) Lookup(payee string) (Record, bool, error) {
	key := normKey(payee)
	if key == "" {
		return Record{}, false, nil
	}

	if h.ttl > 0 {
		h.mu.Lock()
		if e, ok := h.cache[key]; ok && time.Now().Before(e.exp) {
			h.mu.Unlock()
			return e.rec, e.found, nil
		}
		h.mu.Unlock()
	}

	rec, found, err := h.fetch(key)
	if err != nil {
		return Record{}, false, err
	}

	if h.ttl > 0 {
		h.mu.Lock()
		h.cache[key] = cacheEntry{rec: rec, found: found, exp: time.Now().Add(h.ttl)}
		h.mu.Unlock()
	}
	return rec, found, nil
}

func (h *HTTPVendorMaster) fetch(key string) (Record, bool, error) {
	reqURL, err := h.buildURL(key)
	if err != nil {
		return Record{}, false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Record{}, false, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return Record{}, false, fmt.Errorf("system-of-record request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return Record{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Record{}, false, fmt.Errorf("system-of-record returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Record{}, false, fmt.Errorf("reading system-of-record response: %w", err)
	}

	var sr sorResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return Record{}, false, fmt.Errorf("invalid system-of-record response: %w", err)
	}
	if sr.Found != nil && !*sr.Found {
		return Record{}, false, nil
	}
	// A 200 with no identifying fields is treated as "not found".
	if strings.TrimSpace(sr.Payee) == "" && strings.TrimSpace(sr.Name) == "" {
		return Record{}, false, nil
	}
	rec := Record{Payee: sr.Payee, Name: sr.Name}
	if rec.Payee == "" {
		rec.Payee = key
	}
	return rec, true, nil
}

// buildURL substitutes {payee} in the endpoint or appends the payee as a query
// parameter.
func (h *HTTPVendorMaster) buildURL(key string) (string, error) {
	if strings.Contains(h.endpoint, "{payee}") {
		return strings.ReplaceAll(h.endpoint, "{payee}", url.QueryEscape(key)), nil
	}
	u, err := url.Parse(h.endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid system-of-record endpoint: %w", err)
	}
	q := u.Query()
	q.Set(h.param, key)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
