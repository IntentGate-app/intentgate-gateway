// Package velocity is the action velocity and monetary circuit breaker
// (FinOps and safety). It completes what internal/budget left as future work:
// a rolling-window limiter that caps how many calls an agent may make in a
// trailing window AND how much money those calls may move in that window.
//
// It is a physical circuit breaker against Denial-of-Wallet attacks and
// runaway reasoning loops: a poisoned or hallucinating agent that starts
// hammering a paid API or firing repeated transfers trips the breaker at the
// configured limit instead of draining the budget or spamming production.
//
// The window is real and sliding, not a flat daily counter: events older than
// the window fall out, so "5 calls per minute" means the last 60 seconds, not
// since midnight. Monetary amounts come from the same actionir resolution the
// action guard already computes (MagnitudeCents), so no argument is parsed
// twice and no amount is invented. A denied event is not recorded, so a
// blocked burst does not keep the key saturated once the window slides.
package velocity

import "time"

// Limits is the breaker configuration for one key (typically an agent or a
// token within a tenant). A zero field disables that dimension; a zero Window
// disables the breaker entirely.
type Limits struct {
	// MaxCalls caps the number of calls allowed within Window. 0 = no rate cap.
	MaxCalls int
	// Window is the trailing period both caps are measured over.
	Window time.Duration
	// MaxCents caps the summed monetary magnitude (in cents) of calls within
	// Window. 0 = no monetary cap.
	MaxCents int64
}

func (l Limits) enabled() bool { return l.Window > 0 && (l.MaxCalls > 0 || l.MaxCents > 0) }

// Decision is the breaker's verdict for one attempted call.
type Decision struct {
	Allowed bool
	// Reason is "" when allowed, else the audit reason string:
	// "rate_velocity_exceeded" or "monetary_velocity_exceeded".
	Reason string
	// Calls and Cents are the totals in the window INCLUDING this attempt, so
	// the console can show "6 / 5 calls" or "1200 / 1000".
	Calls  int
	Cents  int64
	Limits Limits
}

// Reasons, exported so callers and the audit layer share the strings.
const (
	ReasonRate     = "rate_velocity_exceeded"
	ReasonMonetary = "monetary_velocity_exceeded"
)

// Store keeps the trailing events for a key. The memory implementation backs
// single-node deployments and tests; the same two methods can sit on Redis
// sorted sets for a shared limiter without touching the limiter logic.
type Store interface {
	// Count returns the number of events and the summed cents in the trailing
	// window ending at now. Implementations should prune expired events.
	Count(key string, now time.Time, window time.Duration) (calls int, cents int64)
	// Add records one event of cents at now under key.
	Add(key string, now time.Time, cents int64)
}

// Limiter evaluates attempts against a Store. The clock is injectable so the
// window behaviour is deterministically testable.
type Limiter struct {
	store Store
	now   func() time.Time
}

// New returns a limiter over store. A nil clock uses time.Now.
func New(store Store, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{store: store, now: clock}
}

// Check evaluates whether one call of `cents` under `key` would breach the
// caps, and records it only when allowed. Rate is checked before money so a
// runaway loop trips the call cap first. A disabled config always allows.
func (l *Limiter) Check(key string, cents int64, lim Limits) Decision {
	if !lim.enabled() {
		return Decision{Allowed: true, Limits: lim}
	}
	now := l.now()
	calls, sum := l.store.Count(key, now, lim.Window)
	d := Decision{Limits: lim, Calls: calls + 1, Cents: sum + cents}

	if lim.MaxCalls > 0 && calls+1 > lim.MaxCalls {
		d.Allowed = false
		d.Reason = ReasonRate
		return d
	}
	if lim.MaxCents > 0 && sum+cents > lim.MaxCents {
		d.Allowed = false
		d.Reason = ReasonMonetary
		return d
	}
	l.store.Add(key, now, cents)
	d.Allowed = true
	return d
}
