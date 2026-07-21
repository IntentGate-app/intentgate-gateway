package payloads

import (
	"strings"
	"time"
)

// DefaultTTL is how long a captured response lives when a deployment does not
// say otherwise. Two weeks: long enough to investigate an incident someone
// noticed a week late, short enough that the store never becomes a standing
// second copy of the customer's data.
const DefaultTTL = 14 * 24 * time.Hour

// DefaultMaxBytes caps a single stored body. Responses above it are recorded
// as captured-but-truncated rather than dropped silently, because "this
// returned 40MB" is itself the interesting fact in most investigations.
const DefaultMaxBytes = 256 * 1024

// Policy decides whether a given call's response is retained.
//
// Default deny. Capture is off unless a deployment names what it wants, and
// there is deliberately no "capture everything" switch: an operator who wants
// every tool must write "*" and see themselves do it.
type Policy struct {
	// Enabled is the master switch. False means nothing is ever captured,
	// whatever Tools says.
	Enabled bool

	// Tools lists what to capture. Each entry is an exact tool name or a
	// trailing-* pattern. An agent-to-agent call arrives as a tool named with
	// the agent prefix, so "agent:*" captures inter-agent responses without
	// capturing any tool response, and vice versa.
	Tools []string

	// TTL is how long each captured response survives.
	TTL time.Duration

	// MaxBytes caps a single stored body.
	MaxBytes int
}

// Normalise fills defaults. Called once at startup so the zero values in a
// config file cannot silently mean "keep forever" or "no size limit".
func (p Policy) Normalise() Policy {
	if p.TTL <= 0 {
		p.TTL = DefaultTTL
	}
	if p.MaxBytes <= 0 {
		p.MaxBytes = DefaultMaxBytes
	}
	return p
}

// ShouldCapture reports whether this tool's response is retained.
func (p Policy) ShouldCapture(tool string) bool {
	if !p.Enabled || tool == "" {
		return false
	}
	for _, pat := range p.Tools {
		if matches(pat, tool) {
			return true
		}
	}
	return false
}

// matches implements the same trailing-* rule the authorization rules use, so
// an operator only has to learn one pattern syntax across the product.
func matches(pattern, tool string) bool {
	switch {
	case pattern == "":
		return false
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(tool, strings.TrimSuffix(pattern, "*"))
	default:
		return pattern == tool
	}
}

// Truncate returns the body to store and whether it was cut short.
func (p Policy) Truncate(body []byte) ([]byte, bool) {
	max := p.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if len(body) <= max {
		return body, false
	}
	// Copy rather than reslice: the caller's buffer may be pooled or reused
	// for the response actually sent to the agent, and a stored payload that
	// mutates afterwards would be worse than no payload at all.
	out := make([]byte, max)
	copy(out, body[:max])
	return out, true
}
