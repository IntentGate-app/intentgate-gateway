// Package effectpreview computes a read-only projection of what a tool call
// would do, without executing it. It resolves the call to an Action IR and
// renders a plain-language blast-radius summary ("Irreversible payment of
// EUR 5,000 to ACME BV", "Delete on invoices: affects 4200 records"). When an
// optional read-only Provider is wired, it estimates how many records a scoped
// mutation would touch by asking the target system to count, never to change.
//
// Effect preview is the "look before you leap" control: a high-impact action
// can be simulated and its scope shown to a human before it is allowed to run.
package effectpreview

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// Preview is the read-only projection of a tool call.
type Preview struct {
	Tool           string         `json:"tool"`
	Op             actionir.Op    `json:"op"`
	Resource       string         `json:"resource,omitempty"`
	Scope          actionir.Scope `json:"scope"`
	MagnitudeCents int64          `json:"magnitude_cents"`
	Destination    string         `json:"destination,omitempty"`
	Reversible     bool           `json:"reversible"`
	EstimatedRows  *int64         `json:"estimated_rows,omitempty"`
	BlastRadius    string         `json:"blast_radius"`
}

// Provider is the read-only seam to the target system: given a resource and the
// call args, it returns how many records the mutation would affect. Optional;
// a nil Provider yields a qualitative blast radius only.
type Provider interface {
	CountAffected(resource string, args map[string]any) (int64, error)
}

// Compute resolves the call and builds a Preview. It never mutates anything.
// provider may be nil.
func Compute(tool string, args map[string]any, provider Provider) Preview {
	ir := actionir.Resolve(tool, args)
	p := Preview{
		Tool:           tool,
		Op:             ir.Op,
		Resource:       ir.Resource,
		Scope:          ir.Scope,
		MagnitudeCents: ir.MagnitudeCents,
		Destination:    ir.Destination,
		Reversible:     ir.Reversible,
	}
	// Estimate affected rows for a mutation over a set, if a provider is wired.
	if provider != nil && isMutation(ir.Op) && ir.Scope != actionir.ScopeSingle {
		if n, err := provider.CountAffected(ir.Resource, args); err == nil {
			p.EstimatedRows = &n
		}
	}
	p.BlastRadius = summarize(p)
	return p
}

func isMutation(op actionir.Op) bool {
	switch op {
	case actionir.OpDelete, actionir.OpWrite, actionir.OpCreate, actionir.OpPay:
		return true
	default:
		return false
	}
}

// summarize renders a one-line, plain-language blast radius.
func summarize(p Preview) string {
	res := p.Resource
	if res == "" {
		res = "the target"
	}
	switch p.Op {
	case actionir.OpPay:
		amt := euro(p.MagnitudeCents)
		if p.Destination != "" {
			return fmt.Sprintf("Irreversible payment of %s to %s.", amt, p.Destination)
		}
		return fmt.Sprintf("Irreversible payment of %s.", amt)
	case actionir.OpDelete:
		switch {
		case p.EstimatedRows != nil:
			return fmt.Sprintf("Delete on %s: affects %d record(s). Irreversible.", res, *p.EstimatedRows)
		case p.Scope == actionir.ScopeUnbounded:
			return fmt.Sprintf("Unbounded delete on %s (no filter): affects every record. Irreversible.", res)
		case p.Scope == actionir.ScopeBounded:
			return fmt.Sprintf("Filtered delete on %s: affects a set of records. Irreversible.", res)
		default:
			return fmt.Sprintf("Delete of a single %s record. Irreversible.", res)
		}
	case actionir.OpWrite:
		if p.EstimatedRows != nil {
			return fmt.Sprintf("Update on %s: affects %d record(s).", res, *p.EstimatedRows)
		}
		return fmt.Sprintf("Update on %s (%s scope).", res, p.Scope)
	case actionir.OpCreate:
		return fmt.Sprintf("Creates a new %s record.", res)
	case actionir.OpSend:
		if p.Destination != "" {
			return fmt.Sprintf("Sends an outbound message to %s.", p.Destination)
		}
		return "Sends an outbound message."
	case actionir.OpExecute:
		return fmt.Sprintf("Executes code or a command on %s.", res)
	case actionir.OpRead:
		return fmt.Sprintf("Read-only access to %s. No state change.", res)
	default:
		return fmt.Sprintf("%s on %s (%s scope).", p.Op, res, p.Scope)
	}
}

// euro renders cents as a EUR amount.
func euro(cents int64) string {
	sign := ""
	if cents < 0 {
		sign = "-"
		cents = -cents
	}
	return fmt.Sprintf("%s€%d.%02d", sign, cents/100, cents%100)
}

// HTTPProviderConfig configures an HTTPProvider.
type HTTPProviderConfig struct {
	// Endpoint is a read-only count service: it receives {"resource","args"}
	// and returns {"count": N} without mutating anything.
	Endpoint string
	Headers  map[string]string
	Timeout  time.Duration
}

// HTTPProvider is a read-only Provider backed by a count endpoint.
type HTTPProvider struct {
	client   *http.Client
	endpoint string
	headers  map[string]string
}

// NewHTTPProvider builds an HTTPProvider from cfg.
func NewHTTPProvider(cfg HTTPProviderConfig) *HTTPProvider {
	t := cfg.Timeout
	if t <= 0 {
		t = 5 * time.Second
	}
	h := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		h[k] = v
	}
	return &HTTPProvider{client: &http.Client{Timeout: t}, endpoint: cfg.Endpoint, headers: h}
}

// CountAffected implements Provider against the read-only count endpoint.
func (h *HTTPProvider) CountAffected(resource string, args map[string]any) (int64, error) {
	payload, err := json.Marshal(map[string]any{"resource": resource, "args": args})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), h.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("preview count request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("preview count endpoint returned status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	var out struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, fmt.Errorf("invalid preview count response: %w", err)
	}
	return out.Count, nil
}
