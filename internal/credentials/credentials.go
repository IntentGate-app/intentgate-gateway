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
package credentials

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// header is a parsed "Name: value" HTTP header.
type header struct {
	name  string
	value string
}

// Store maps a tool name to the credential header that authenticates
// calls to that tool's upstream.
type Store struct {
	mu      sync.RWMutex
	perTool map[string]header
}

// New builds a Store from a tool -> "Header-Name: value" map. Used at
// boot to seed from configuration; entries can be changed later with
// Set / Remove (e.g. by the console).
func New(perTool map[string]string) (*Store, error) {
	s := &Store{perTool: make(map[string]header, len(perTool))}
	for tool, raw := range perTool {
		h, err := parseHeader(raw)
		if err != nil {
			return nil, fmt.Errorf("credential for tool %q: %w", tool, err)
		}
		s.perTool[strings.TrimSpace(tool)] = h
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
	if h, ok := s.perTool[tool]; ok {
		return map[string]string{h.name: h.value}
	}
	return nil
}

// Set installs or replaces the credential for a tool. This is what
// console-managed rotation calls — supplying a new value for an
// existing tool rotates it live.
func (s *Store) Set(tool, raw string) error {
	h, err := parseHeader(raw)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.perTool[strings.TrimSpace(tool)] = h
	return nil
}

// Remove deletes a tool's per-tool credential; that tool then falls
// back to the global upstream credential.
func (s *Store) Remove(tool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.perTool, strings.TrimSpace(tool))
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
