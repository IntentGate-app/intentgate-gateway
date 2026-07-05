package flowmap

import "testing"

func cfg() Config { return Config{AgentToolPrefix: "agent:"} }

func findEdge(g Graph, from, to string) *Edge {
	for i := range g.Edges {
		if g.Edges[i].From == from && g.Edges[i].To == to {
			return &g.Edges[i]
		}
	}
	return nil
}

func nodeKind(g Graph, id string) (NodeKind, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n.Kind, true
		}
	}
	return "", false
}

// An ordinary tool call yields a north-south edge from an agent node to a tool
// node, with the tool classified as a tool.
func TestExtract_NorthSouthEdge(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "agent-finance", Tool: "read_invoice", Tenant: "acme", Decision: "allow"},
	})
	e := findEdge(g, "agent-finance", "read_invoice")
	if e == nil {
		t.Fatal("expected agent-finance -> read_invoice edge")
	}
	if e.Kind != EdgeNorthSouth || e.Allow != 1 || e.Total != 1 {
		t.Fatalf("edge = %+v", e)
	}
	if k, _ := nodeKind(g, "read_invoice"); k != NodeTool {
		t.Fatalf("read_invoice kind = %s, want tool", k)
	}
	if k, _ := nodeKind(g, "agent-finance"); k != NodeAgent {
		t.Fatalf("agent-finance kind = %s, want agent", k)
	}
}

// A call to an agent-prefixed tool yields an east-west edge between two agent
// nodes, with the callee parsed out of the tool name.
func TestExtract_EastWestEdge(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "agent-procure", Tool: "agent:agent-finance", Tenant: "acme", Decision: "allow"},
	})
	e := findEdge(g, "agent-procure", "agent-finance")
	if e == nil {
		t.Fatal("expected agent-procure -> agent-finance east-west edge")
	}
	if e.Kind != EdgeEastWest {
		t.Fatalf("edge kind = %s, want east_west", e.Kind)
	}
	if k, _ := nodeKind(g, "agent-finance"); k != NodeAgent {
		t.Fatalf("callee agent-finance kind = %s, want agent", k)
	}
}

// Repeated calls on the same edge aggregate by decision.
func TestExtract_AggregatesDecisions(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "a", Tool: "t", Decision: "allow"},
		{Agent: "a", Tool: "t", Decision: "allow"},
		{Agent: "a", Tool: "t", Decision: "block"},
		{Agent: "a", Tool: "t", Decision: "escalate"},
	})
	e := findEdge(g, "a", "t")
	if e == nil {
		t.Fatal("expected a -> t edge")
	}
	if e.Allow != 2 || e.Block != 1 || e.Escalate != 1 || e.Total != 4 {
		t.Fatalf("counts = %+v", e)
	}
}

// Distinct tenants on an edge are collected and sorted; duplicates collapse.
func TestExtract_CollectsTenants(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "a", Tool: "t", Tenant: "beta", Decision: "allow"},
		{Agent: "a", Tool: "t", Tenant: "acme", Decision: "allow"},
		{Agent: "a", Tool: "t", Tenant: "acme", Decision: "allow"},
	})
	e := findEdge(g, "a", "t")
	if len(e.Tenants) != 2 || e.Tenants[0] != "acme" || e.Tenants[1] != "beta" {
		t.Fatalf("tenants = %v, want [acme beta]", e.Tenants)
	}
}

// Calls with an empty agent or tool are skipped, and a bare prefix is skipped.
func TestExtract_SkipsIncomplete(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "", Tool: "t", Decision: "allow"},
		{Agent: "a", Tool: "", Decision: "allow"},
		{Agent: "a", Tool: "agent:", Decision: "allow"},
	})
	if len(g.Edges) != 0 {
		t.Fatalf("expected no edges, got %+v", g.Edges)
	}
	if len(g.Nodes) != 0 {
		t.Fatalf("expected no nodes, got %+v", g.Nodes)
	}
}

// With no prefix configured, an agent-looking tool is just a tool.
func TestExtract_NoPrefixMeansAllNorthSouth(t *testing.T) {
	g := Extract(Config{}, []Call{
		{Agent: "a", Tool: "agent:agent-finance", Decision: "allow"},
	})
	e := findEdge(g, "a", "agent:agent-finance")
	if e == nil || e.Kind != EdgeNorthSouth {
		t.Fatalf("expected north-south edge, got %+v", g.Edges)
	}
}

// Output is deterministic: nodes and edges are sorted.
func TestExtract_DeterministicOrder(t *testing.T) {
	g := Extract(cfg(), []Call{
		{Agent: "zeta", Tool: "b", Decision: "allow"},
		{Agent: "alpha", Tool: "a", Decision: "allow"},
		{Agent: "alpha", Tool: "z", Decision: "allow"},
	})
	if g.Edges[0].From != "alpha" || g.Edges[0].To != "a" {
		t.Fatalf("edges not sorted: %+v", g.Edges)
	}
	if g.Nodes[0].ID != "a" {
		t.Fatalf("nodes not sorted: %+v", g.Nodes)
	}
}
