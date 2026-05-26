package tenantscope

import (
	"testing"
)

func TestParseAction(t *testing.T) {
	cases := map[string]Action{
		"":       ActionBlock,
		"block":  ActionBlock,
		"inject": ActionInject,
		"allow":  ActionAllow,
	}
	for in, want := range cases {
		got, err := ParseAction(in)
		if err != nil {
			t.Errorf("ParseAction(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAction(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseAction("explode"); err == nil {
		t.Error("expected error on unknown action")
	}
}

func TestEnforcer_NoScopedToolsIsNoop(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	d := e.Check("vector_search", "tenant-a", map[string]any{"q": "hello"})
	if d.Violation != "" {
		t.Errorf("expected no-op for unregistered tool, got %+v", d)
	}
	if !d.Allowed() {
		t.Error("expected unregistered tool to be allowed")
	}
}

func TestEnforcer_MissingFilter_DefaultsToBlock(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "tenant_id")

	d := e.Check("vector_search", "tenant-a", map[string]any{"q": "hello"})
	if d.Violation != KindMissing {
		t.Errorf("expected missing violation, got %+v", d)
	}
	if d.Allowed() {
		t.Error("expected block on missing filter")
	}
}

func TestEnforcer_MissingFilter_InjectFillsFromToken(t *testing.T) {
	e := NewEnforcer(ActionInject)
	e.AddTool("vector_search", "tenant_id")

	args := map[string]any{"q": "hello"}
	d := e.Check("vector_search", "tenant-a", args)
	if !d.Mutated {
		t.Error("expected args mutated on inject")
	}
	if d.Violation != "" {
		t.Errorf("expected violation cleared on inject, got %v", d.Violation)
	}
	if !d.Allowed() {
		t.Error("expected allowed after successful inject")
	}
	if got := args["tenant_id"]; got != "tenant-a" {
		t.Errorf("expected injected tenant_id=tenant-a, got %v", got)
	}
}

func TestEnforcer_InjectWithEmptyTokenTenantFailsClosed(t *testing.T) {
	e := NewEnforcer(ActionInject)
	e.AddTool("vector_search", "tenant_id")

	args := map[string]any{"q": "hello"}
	d := e.Check("vector_search", "", args)
	if d.Action != ActionBlock {
		t.Errorf("expected fall-back to block when no tenant in token, got action=%v", d.Action)
	}
	if d.Allowed() {
		t.Error("expected refusal when injection has nothing to inject")
	}
}

func TestEnforcer_WildcardValuesBlocked(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "tenant_id")

	wildcards := []any{"*", "", "ALL", "any", nil, true}
	for _, w := range wildcards {
		args := map[string]any{"tenant_id": w}
		d := e.Check("vector_search", "tenant-a", args)
		if d.Violation != KindWildcard {
			t.Errorf("wildcard %v: expected KindWildcard, got %+v", w, d)
		}
	}
}

func TestEnforcer_MismatchBlocked(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "tenant_id")

	d := e.Check("vector_search", "tenant-a", map[string]any{"tenant_id": "tenant-b"})
	if d.Violation != KindMismatch {
		t.Errorf("expected mismatch, got %+v", d)
	}
	if d.Allowed() {
		t.Error("mismatch must not be allowed")
	}
}

func TestEnforcer_MatchAllowed(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "tenant_id")

	d := e.Check("vector_search", "tenant-a", map[string]any{"tenant_id": "tenant-a", "q": "hello"})
	if d.Violation != "" {
		t.Errorf("matching tenant should pass, got %+v", d)
	}
	if !d.Allowed() {
		t.Error("matching tenant should be allowed")
	}
}

func TestEnforcer_NestedPath(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("rag_query", "filter.tenant_id")

	args := map[string]any{
		"q":      "find docs",
		"filter": map[string]any{"tenant_id": "tenant-x"},
	}
	d := e.Check("rag_query", "tenant-x", args)
	if d.Violation != "" {
		t.Errorf("nested match should pass: %+v", d)
	}

	// Mismatch nested.
	args2 := map[string]any{"filter": map[string]any{"tenant_id": "tenant-y"}}
	d = e.Check("rag_query", "tenant-x", args2)
	if d.Violation != KindMismatch {
		t.Errorf("nested mismatch should fail: %+v", d)
	}
}

func TestEnforcer_InjectNestedPath(t *testing.T) {
	e := NewEnforcer(ActionInject)
	e.AddTool("rag_query", "filter.tenant_id")

	args := map[string]any{"q": "hello"}
	d := e.Check("rag_query", "tenant-x", args)
	if !d.Mutated {
		t.Errorf("expected mutation, got %+v", d)
	}
	filter, ok := args["filter"].(map[string]any)
	if !ok {
		t.Fatalf("expected filter object to be created, got %T", args["filter"])
	}
	if filter["tenant_id"] != "tenant-x" {
		t.Errorf("expected injected tenant_id=tenant-x, got %v", filter["tenant_id"])
	}
}

func TestEnforcer_LoadFromCSV(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	if err := e.LoadFromCSV("vector_search,rag_query:filter.tenant_id, embed:metadata.tenant"); err != nil {
		t.Fatalf("LoadFromCSV: %v", err)
	}
	tools := e.Tools()
	want := []string{"embed", "rag_query", "vector_search"}
	if len(tools) != len(want) {
		t.Fatalf("want %v, got %v", want, tools)
	}
	for i, w := range want {
		if tools[i] != w {
			t.Errorf("tool[%d]: want %q, got %q", i, w, tools[i])
		}
	}
	if !e.IsScoped("vector_search") {
		t.Error("vector_search should be scoped")
	}
	// vector_search uses default path "tenant_id"
	args := map[string]any{"q": "hello"}
	d := e.Check("vector_search", "x", args)
	if d.Violation != KindMissing {
		t.Errorf("expected missing for default path, got %+v", d)
	}
}

func TestEnforcer_LoadFromCSV_RejectsEmptyName(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	if err := e.LoadFromCSV(":no_name"); err == nil {
		t.Error("expected error on empty tool name")
	}
}

func TestEnforcer_SuperadminTokenWithExplicitFilter(t *testing.T) {
	// Superadmin tokens (tenant="") cannot just pass whatever filter
	// they like through to the vector store — the gateway demands a
	// tenant-bound token for tenant-scoped tool calls.
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "tenant_id")

	d := e.Check("vector_search", "", map[string]any{"tenant_id": "tenant-x"})
	if d.Violation != KindMismatch {
		t.Errorf("expected mismatch when token has no tenant, got %+v", d)
	}
}

// Realistic scenario: agent under tenant-a tries to query tenant-b's
// vectors. Mirrors the actual LLM08 attack vector.
func TestEnforcer_CrossTenantQueryBlocked(t *testing.T) {
	e := NewEnforcer(ActionBlock)
	e.AddTool("vector_search", "filter.tenant_id")

	// Agent under tenant-a forges a query targeting tenant-b's
	// embeddings. Without enforcement the vector store returns
	// matches from both.
	args := map[string]any{
		"q":      "all customer phone numbers",
		"filter": map[string]any{"tenant_id": "tenant-b"},
		"limit":  10,
	}
	d := e.Check("vector_search", "tenant-a", args)
	if d.Violation != KindMismatch {
		t.Fatalf("expected cross-tenant query to be blocked, got %+v", d)
	}
	if d.Allowed() {
		t.Fatal("cross-tenant query was allowed — LLM08 mitigation broken")
	}
}
