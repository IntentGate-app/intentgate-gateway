package killswitch

import (
	"context"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		e    Entry
		ok   bool
	}{
		{"global ok", Entry{Type: ScopeGlobal}, true},
		{"global with tenant is invalid", Entry{Type: ScopeGlobal, Tenant: "a"}, false},
		{"global with value is invalid", Entry{Type: ScopeGlobal, Value: "x"}, false},
		{"tenant ok", Entry{Type: ScopeTenant, Tenant: "a"}, true},
		{"tenant missing tenant", Entry{Type: ScopeTenant}, false},
		{"tenant with value is invalid", Entry{Type: ScopeTenant, Tenant: "a", Value: "x"}, false},
		{"agent ok", Entry{Type: ScopeAgent, Tenant: "a", Value: "x"}, true},
		{"agent missing value", Entry{Type: ScopeAgent, Tenant: "a"}, false},
		{"agent missing tenant", Entry{Type: ScopeAgent, Value: "x"}, false},
		{"unknown scope", Entry{Type: "weird"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.e.Validate()
			if c.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !c.ok && err == nil {
				t.Fatalf("want invalid, got nil")
			}
		})
	}
}

// runKillContract exercises the Store interface. Both MemoryStore and
// (when a DSN is set) PostgresStore should pass identically.
func runKillContract(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()

	if active, _, err := s.Active(ctx, "acme", "agent1"); err != nil || active {
		t.Fatalf("fresh: active=%v err=%v; want false, nil", active, err)
	}

	// Agent kill in acme.
	if err := s.Engage(ctx, Entry{Type: ScopeAgent, Tenant: "acme", Value: "agent1", Reason: "compromise"}); err != nil {
		t.Fatalf("engage agent: %v", err)
	}
	if active, e, err := s.Active(ctx, "acme", "agent1"); err != nil || !active || e.Type != ScopeAgent {
		t.Fatalf("agent1 should be halted: active=%v type=%v err=%v", active, e.Type, err)
	}
	// Same agent id in a different tenant is NOT halted (collision safety).
	if active, _, err := s.Active(ctx, "other", "agent1"); err != nil || active {
		t.Fatalf("cross-tenant agent id must not halt: active=%v err=%v", active, err)
	}
	// A different agent in acme is not halted.
	if active, _, err := s.Active(ctx, "acme", "agent2"); err != nil || active {
		t.Fatalf("agent2 must not halt: active=%v err=%v", active, err)
	}

	// Tenant kill halts every agent in acme.
	if err := s.Engage(ctx, Entry{Type: ScopeTenant, Tenant: "acme"}); err != nil {
		t.Fatalf("engage tenant: %v", err)
	}
	if active, _, err := s.Active(ctx, "acme", "agent2"); err != nil || !active {
		t.Fatalf("tenant halt should cover agent2: active=%v err=%v", active, err)
	}
	if active, _, err := s.Active(ctx, "other", "agent9"); err != nil || active {
		t.Fatalf("other tenant must be unaffected: active=%v err=%v", active, err)
	}

	// Global halts everyone, and is the most-specific match reported last.
	if err := s.Engage(ctx, Entry{Type: ScopeGlobal, Reason: "incident"}); err != nil {
		t.Fatalf("engage global: %v", err)
	}
	if active, e, err := s.Active(ctx, "other", "agent9"); err != nil || !active || e.Type != ScopeGlobal {
		t.Fatalf("global halt expected: active=%v type=%v err=%v", active, e.Type, err)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("want 3 engaged entries, got %d", len(list))
	}

	// Release global; other/agent9 clear, acme still tenant-halted.
	if err := s.Release(ctx, ScopeGlobal, "", ""); err != nil {
		t.Fatalf("release global: %v", err)
	}
	if active, _, err := s.Active(ctx, "other", "agent9"); err != nil || active {
		t.Fatalf("after global release, other must clear: active=%v err=%v", active, err)
	}
	if active, _, err := s.Active(ctx, "acme", "agent2"); err != nil || !active {
		t.Fatalf("acme still tenant-halted: active=%v err=%v", active, err)
	}

	// Release tenant + agent → acme fully clear.
	if err := s.Release(ctx, ScopeTenant, "acme", ""); err != nil {
		t.Fatalf("release tenant: %v", err)
	}
	if err := s.Release(ctx, ScopeAgent, "acme", "agent1"); err != nil {
		t.Fatalf("release agent: %v", err)
	}
	if active, _, err := s.Active(ctx, "acme", "agent1"); err != nil || active {
		t.Fatalf("acme fully released: active=%v err=%v", active, err)
	}

	// Release of an absent entry is not an error (idempotent).
	if err := s.Release(ctx, ScopeAgent, "acme", "ghost"); err != nil {
		t.Fatalf("release absent should be no-op: %v", err)
	}
}

func TestMemoryStoreContract(t *testing.T) {
	runKillContract(t, NewMemoryStore())
}

func TestEngageIdempotentKeepsSetAt(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.Engage(ctx, Entry{Type: ScopeTenant, Tenant: "acme", Reason: "first"}); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("want 1 entry, got %d", len(list))
	}
	first := list[0].SetAt

	time.Sleep(2 * time.Millisecond)
	if err := s.Engage(ctx, Entry{Type: ScopeTenant, Tenant: "acme", Reason: "second"}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.List(ctx)
	if len(list) != 1 {
		t.Fatalf("re-engage must be idempotent (1 entry), got %d", len(list))
	}
	if !list[0].SetAt.Equal(first) {
		t.Fatalf("SetAt must not change on re-engage: %v -> %v", first, list[0].SetAt)
	}
	if list[0].Reason != "second" {
		t.Fatalf("reason should update on re-engage: got %q", list[0].Reason)
	}
}

func TestInvalidEngageRejected(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.Engage(ctx, Entry{Type: ScopeAgent, Tenant: "acme"}); err == nil {
		t.Fatalf("agent kill without value should be rejected")
	}
}
