// Package credentials brokers per-tool upstream credentials.
//
// The real secret each tool server requires lives on the gateway, not
// in any agent. When the gateway forwards an authorized call, it looks
// up the credential for that specific tool and injects it on the
// outbound request. Tools without a specific entry fall back to the
// gateway's single global upstream credential (the v1 behavior).
//
// The store is safe for concurrent use and its entries can be replaced
// at runtime, so console-managed rotation takes effect without a
// gateway restart.
//
// Alongside each secret the durable store records governance metadata —
// when it was last rotated (updated_at), an optional accountable owner,
// and an optional expiry — so the console can show a real change-control
// picture. The metadata is never the secret: values remain write-only.
package credentials

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// header is a parsed "Name: value" HTTP header.
type header struct {
	name  string
	value string
}

// entry is one stored credential plus its governance metadata. The
// value is the injected secret; rotatedAt/owner/expiresAt are the
// redacted-safe fields surfaced to the console.
type entry struct {
	name      string
	value     string
	rotatedAt time.Time // last set/rotate; zero when unknown (env-configured)
	owner     string    // accountable owner, "" when none
	expiresAt time.Time // zero when the credential has no expiry
}

// Store maps a tool name to the credential header that authenticates
// calls to that tool's upstream. When db is non-nil the store is
// durable (console-managed): Set/Remove persist encrypted to Postgres
// and Reload refreshes from it; when db is nil the store is in-memory
// only (env-configured).
type Store struct {
	mu      sync.RWMutex
	perTool map[string]entry
	db      *PostgresStore
}

// Info is a redacted view of one entry — the tool, the header NAME, and
// governance metadata. Secret values are never exposed. Timestamps are
// RFC3339 and omitted when unknown, so an env-configured store (which
// has no rotation record) simply doesn't carry them.
type Info struct {
	Tool      string `json:"tool"`
	Header    string `json:"header"`
	RotatedAt string `json:"rotated_at,omitempty"`
	Owner     string `json:"owner,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// New builds an in-memory Store from a tool -> "Header-Name: value"
// map (the env-configured path). Entries can be changed later with
// Set / Remove. Env-configured entries carry no rotation timestamp,
// owner, or expiry — those are only tracked by the durable store.
func New(perTool map[string]string) (*Store, error) {
	s := &Store{perTool: make(map[string]entry, len(perTool))}
	for tool, raw := range perTool {
		h, err := parseHeader(raw)
		if err != nil {
			return nil, fmt.Errorf("credential for tool %q: %w", tool, err)
		}
		s.perTool[strings.TrimSpace(tool)] = entry{name: h.name, value: h.value}
	}
	return s, nil
}

// NewPostgres builds a durable, console-managed Store: it loads the
// persisted entries (with metadata) from db, then seeds any env-provided
// tools that aren't already persisted (first-boot migration). Subsequent
// changes go through Set / SetMeta / Remove and persist.
func NewPostgres(ctx context.Context, db *PostgresStore, seed map[string]string) (*Store, error) {
	s := &Store{perTool: map[string]entry{}, db: db}
	persisted, err := db.loadAllMeta(ctx)
	if err != nil {
		return nil, err
	}
	for tool, pc := range persisted {
		h, err := parseHeader(pc.raw)
		if err != nil {
			return nil, fmt.Errorf("persisted credential for tool %q: %w", tool, err)
		}
		s.perTool[tool] = entry{
			name:      h.name,
			value:     h.value,
			rotatedAt: pc.rotatedAt,
			owner:     pc.owner,
			expiresAt: pc.expiresAt,
		}
	}
	for tool, raw := range seed {
		if _, ok := s.perTool[strings.TrimSpace(tool)]; ok {
			continue
		}
		if err := s.Set(ctx, tool, raw); err != nil {
			return nil, fmt.Errorf("seed credential for tool %q: %w", tool, err)
		}
	}
	return s, nil
}

// HeaderFor returns the header to inject for tool, or nil when no
// per-tool credential is configured (the caller then falls back to the
// gateway's global upstream credential). A nil *Store returns nil so
// callers don't need a guard.
func (s *Store) HeaderFor(tool string) map[string]string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e, ok := s.perTool[tool]; ok {
		return map[string]string{e.name: e.value}
	}
	return nil
}

// Set installs or replaces the credential for a tool with no owner or
// expiry. Kept for existing callers; delegates to SetMeta.
func (s *Store) Set(ctx context.Context, tool, raw string) error {
	return s.SetMeta(ctx, tool, raw, "", time.Time{})
}

// SetMeta installs or replaces the credential for a tool together with
// its governance metadata, persisting to Postgres first when durable.
// This is what console-managed rotation calls — a new value for an
// existing tool rotates it live and stamps a fresh rotation time.
// A zero expiresAt means "no expiry".
func (s *Store) SetMeta(ctx context.Context, tool, raw, owner string, expiresAt time.Time) error {
	tool = strings.TrimSpace(tool)
	owner = strings.TrimSpace(owner)
	h, err := parseHeader(raw)
	if err != nil {
		return err
	}
	if s.db != nil {
		if err := s.db.upsertMeta(ctx, tool, raw, owner, expiresAt); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.perTool[tool] = entry{
		name:      h.name,
		value:     h.value,
		rotatedAt: time.Now().UTC(),
		owner:     owner,
		expiresAt: expiresAt,
	}
	s.mu.Unlock()
	return nil
}

// Remove deletes a tool's per-tool credential (persisting first when
// durable); that tool then falls back to the global upstream credential.
func (s *Store) Remove(ctx context.Context, tool string) error {
	tool = strings.TrimSpace(tool)
	if s.db != nil {
		if err := s.db.remove(ctx, tool); err != nil {
			return err
		}
	}
	s.mu.Lock()
	delete(s.perTool, tool)
	s.mu.Unlock()
	return nil
}

// Reload refreshes the in-memory view (with metadata) from Postgres.
// Called on a timer so changes made on one replica propagate to the
// others. No-op for an in-memory (env-configured) store.
func (s *Store) Reload(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	persisted, err := s.db.loadAllMeta(ctx)
	if err != nil {
		return err
	}
	next := make(map[string]entry, len(persisted))
	for tool, pc := range persisted {
		h, err := parseHeader(pc.raw)
		if err != nil {
			return err
		}
		next[tool] = entry{
			name:      h.name,
			value:     h.value,
			rotatedAt: pc.rotatedAt,
			owner:     pc.owner,
			expiresAt: pc.expiresAt,
		}
	}
	s.mu.Lock()
	s.perTool = next
	s.mu.Unlock()
	return nil
}

// List returns a redacted view of every entry (tool + header name +
// metadata, no values), sorted by tool.
func (s *Store) List() []Info {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.perTool))
	for t, e := range s.perTool {
		inf := Info{Tool: t, Header: e.name, Owner: e.owner}
		if !e.rotatedAt.IsZero() {
			inf.RotatedAt = e.rotatedAt.UTC().Format(time.RFC3339)
		}
		if !e.expiresAt.IsZero() {
			inf.ExpiresAt = e.expiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, inf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// Close releases the Postgres pool when durable.
func (s *Store) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}

// Tools lists the tool names that have a per-tool credential, sorted.
// Secret values are never returned — this is for listing/redacted UIs.
func (s *Store) Tools() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.perTool))
	for t := range s.perTool {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// parseHeader splits a "Header-Name: value" string. Both sides are
// required.
func parseHeader(raw string) (header, error) {
	name, value, ok := strings.Cut(strings.TrimSpace(raw), ":")
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if !ok || name == "" || value == "" {
		return header{}, fmt.Errorf(`must be "Header-Name: value"`)
	}
	return header{name: name, value: value}, nil
}
