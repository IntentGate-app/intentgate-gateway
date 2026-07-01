// Package killswitch provides an operator "big red button": an
// incident-response circuit breaker that halts agent traffic at three
// scopes — a single agent, a whole tenant, or globally — independent of
// per-token revocation.
//
// # Why it is separate from revocation
//
// Revocation (see internal/revocation) invalidates one capability token
// by its JTI. That is surgical: you must know which token to drop. The
// kill switch is the opposite tool. It denies whole classes of traffic
// without knowing which tokens are outstanding, which is what an
// operator actually reaches for during an incident: "stop that agent
// now", or "freeze everything while we investigate". Engaging and
// releasing are both instant and reversible.
//
// # Hot path
//
// [Store.Active] is consulted first in the capability check, before
// revocation and caveat evaluation, so an engaged switch fails closed
// on every request it covers. Like revocation, a store error MUST be
// treated as "halted" by callers — a partial outage of the kill-switch
// store must never become a quiet bypass of an engaged breaker.
//
// # Scopes and tenancy
//
//   - Global — halts every agent in every tenant. Superadmin only.
//   - Tenant — halts every agent in one tenant. Set by that tenant's
//     admin or the superadmin.
//   - Agent  — halts one agent within one tenant. Agent IDs are only
//     unique within a tenant, so an agent entry always carries the
//     tenant it applies to; the hot-path match requires both to agree,
//     which closes the cross-tenant agent-ID collision vector.
package killswitch

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScopeType names what an [Entry] halts.
type ScopeType string

const (
	// ScopeGlobal halts all agents in all tenants.
	ScopeGlobal ScopeType = "global"
	// ScopeTenant halts all agents in one tenant.
	ScopeTenant ScopeType = "tenant"
	// ScopeAgent halts one agent within one tenant.
	ScopeAgent ScopeType = "agent"
)

// ErrInvalidScope is returned when an Entry does not describe a valid
// (type, tenant, value) combination.
var ErrInvalidScope = errors.New("killswitch: invalid scope")

// Entry is one engaged kill.
type Entry struct {
	// Type is the scope: global, tenant, or agent.
	Type ScopeType `json:"type"`
	// Tenant is the tenant the kill applies within. Empty for global;
	// the target tenant for tenant and agent scopes.
	Tenant string `json:"tenant,omitempty"`
	// Value is the agent ID for agent scope. Empty for global and
	// tenant scope.
	Value string `json:"value,omitempty"`
	// Reason is operator-supplied context. May be empty.
	Reason string `json:"reason,omitempty"`
	// SetAt is when the kill was engaged, in UTC.
	SetAt time.Time `json:"set_at"`
	// SetBy is the tenant of the admin who engaged it; empty means the
	// superadmin engaged it.
	SetBy string `json:"set_by,omitempty"`
}

// Validate reports whether the entry describes a coherent scope.
func (e Entry) Validate() error {
	switch e.Type {
	case ScopeGlobal:
		if e.Tenant != "" || e.Value != "" {
			return ErrInvalidScope
		}
	case ScopeTenant:
		if strings.TrimSpace(e.Tenant) == "" || e.Value != "" {
			return ErrInvalidScope
		}
	case ScopeAgent:
		if strings.TrimSpace(e.Tenant) == "" || strings.TrimSpace(e.Value) == "" {
			return ErrInvalidScope
		}
	default:
		return ErrInvalidScope
	}
	return nil
}

// key is the storage/dedup key for an entry: one active kill per
// (type, tenant, value).
func (e Entry) key() string {
	return string(e.Type) + "|" + e.Tenant + "|" + e.Value
}

// Store is the contract every kill-switch backend implements.
//
// Implementations MUST be safe for concurrent use: Active is on the
// gateway hot path and called under any number of concurrent requests.
type Store interface {
	// Active reports whether traffic for (tenant, agentID) is halted by
	// any engaged entry: a global kill, a kill on this tenant, or a kill
	// on this specific agent within this tenant. On a match it returns
	// the matching Entry so the caller can log and audit which breaker
	// fired. A non-nil error means the caller could not determine the
	// answer; production callers MUST fail closed.
	Active(ctx context.Context, tenant, agentID string) (bool, Entry, error)

	// Engage records a kill. Idempotent per (type, tenant, value):
	// re-engaging updates the reason but keeps the original SetAt.
	Engage(ctx context.Context, e Entry) error

	// Release removes the kill identified by (type, tenant, value). Not
	// an error if no matching entry is engaged.
	Release(ctx context.Context, t ScopeType, tenant, value string) error

	// List returns all engaged kills, most-recent first. Not on the
	// request path.
	List(ctx context.Context) ([]Entry, error)
}

// MemoryStore keeps engaged kills in a process-local map. Lost on
// gateway restart and not shared across replicas — fine for dev and
// single-node installs. Production multi-replica deployments use the
// Postgres store so an engaged breaker is honoured fleet-wide.
//
// Safe for concurrent use.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]Entry
}

// NewMemoryStore returns an empty in-memory kill-switch store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: make(map[string]Entry)}
}

// Active implements [Store]. O(1): three keyed lookups.
func (s *MemoryStore) Active(_ context.Context, tenant, agentID string) (bool, Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.entries[(Entry{Type: ScopeGlobal}).key()]; ok {
		return true, e, nil
	}
	if tenant != "" {
		if e, ok := s.entries[(Entry{Type: ScopeTenant, Tenant: tenant}).key()]; ok {
			return true, e, nil
		}
		if agentID != "" {
			if e, ok := s.entries[(Entry{Type: ScopeAgent, Tenant: tenant, Value: agentID}).key()]; ok {
				return true, e, nil
			}
		}
	}
	return false, Entry{}, nil
}

// Engage implements [Store].
func (s *MemoryStore) Engage(_ context.Context, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.entries[e.key()]; ok {
		existing.Reason = e.Reason
		s.entries[e.key()] = existing
		return nil
	}
	if e.SetAt.IsZero() {
		e.SetAt = time.Now().UTC()
	}
	s.entries[e.key()] = e
	return nil
}

// Release implements [Store].
func (s *MemoryStore) Release(_ context.Context, t ScopeType, tenant, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, (Entry{Type: t, Tenant: tenant, Value: value}).key())
	return nil
}

// List implements [Store].
func (s *MemoryStore) List(_ context.Context) ([]Entry, error) {
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].SetAt.After(out[j].SetAt) })
	return out, nil
}
