package zonescope

import "testing"

// A base config: the support zone may only reach two read-only tools; the
// finance zone may reach everything but only in the "acme" tenant.
func base() Config {
	return Config{
		Scopes: map[string]Scope{
			"support": {Tools: []string{"read_invoice", "read_ticket"}},
			"finance": {Tools: []string{WildcardAll}, Tenants: []string{"acme"}},
		},
	}
}

// A zone with no configured scope is a pass-through, not a decision.
func TestCheck_UnscopedZoneIsNoOp(t *testing.T) {
	g := New(base())
	r := g.Check("procurement", "acme", "transfer_funds")
	if r.Enforced {
		t.Fatalf("procurement has no scope, should not be enforced")
	}
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (pass-through)", r.Verdict)
	}
}

// A tool on the zone's allowlist is permitted.
func TestCheck_AllowedTool(t *testing.T) {
	g := New(base())
	r := g.Check("support", "acme", "read_invoice")
	if !r.Enforced {
		t.Fatalf("support has a scope, should be enforced")
	}
	if r.Verdict != VerdictAllow {
		t.Fatalf("verdict = %s, want allow (%s)", r.Verdict, r.Reason)
	}
}

// A tool NOT on the allowlist is denied: this is the containment case, the
// support zone cannot reach a money-moving tool.
func TestCheck_ToolNotInScopeDenied(t *testing.T) {
	g := New(base())
	r := g.Check("support", "acme", "transfer_funds")
	if r.Verdict != VerdictDeny {
		t.Fatalf("transfer_funds should be denied for support, got %s", r.Verdict)
	}
}

// An empty Tools list denies every tool (fail closed).
func TestCheck_EmptyToolsDeniesAll(t *testing.T) {
	g := New(Config{Scopes: map[string]Scope{"locked": {}}})
	r := g.Check("locked", "acme", "read_invoice")
	if r.Verdict != VerdictDeny {
		t.Fatalf("empty tool list should deny all, got %s", r.Verdict)
	}
}

// The wildcard entry allows every tool.
func TestCheck_WildcardAllowsAllTools(t *testing.T) {
	g := New(base())
	r := g.Check("finance", "acme", "some_new_tool")
	if r.Verdict != VerdictAllow {
		t.Fatalf("wildcard should allow any tool, got %s (%s)", r.Verdict, r.Reason)
	}
}

// A tenant restriction denies calls outside the allowed tenants, even for a
// wildcard tool allowlist.
func TestCheck_TenantRestrictionDenies(t *testing.T) {
	g := New(base())
	r := g.Check("finance", "other-corp", "read_invoice")
	if r.Verdict != VerdictDeny {
		t.Fatalf("finance may only act in acme, got %s for other-corp", r.Verdict)
	}
}

// With no tenant restriction, any tenant is accepted.
func TestCheck_NoTenantRestrictionAllowsAnyTenant(t *testing.T) {
	g := New(base())
	r := g.Check("support", "any-tenant", "read_ticket")
	if r.Verdict != VerdictAllow {
		t.Fatalf("support has no tenant restriction, got %s (%s)", r.Verdict, r.Reason)
	}
}

// Snapshot round-trips the config and is a copy (mutating it is inert).
func TestSnapshot(t *testing.T) {
	g := New(base())
	snap := g.Snapshot()
	if got := snap.Scopes["support"].Tools; len(got) != 2 || got[0] != "read_invoice" {
		t.Fatalf("snapshot support tools = %v", got)
	}
	if got := snap.Scopes["finance"].Tenants; len(got) != 1 || got[0] != "acme" {
		t.Fatalf("snapshot finance tenants = %v", got)
	}
	// Mutating the snapshot must not change the guard's decision.
	snap.Scopes["support"].Tools[0] = "mutated"
	if r := g.Check("support", "acme", "read_invoice"); r.Verdict != VerdictAllow {
		t.Fatalf("guard changed after mutating snapshot: %s", r.Verdict)
	}
}
