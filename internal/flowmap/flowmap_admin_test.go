package flowmap

import "testing"

// Admin operations carry an agent_id — the agent a token was minted for — but
// nobody called anything. On the estate map they became tools agents reach,
// and the policy overlay then reported that group scope "would now block"
// agent-to-admin/mint routes that do not exist.
func TestExtractSkipsAdminOperations(t *testing.T) {
	g := Extract(Config{AgentToolPrefix: "agent:"}, []Call{
		{Agent: "agent-support-1", Tool: "admin/mint", Decision: "allow"},
		{Agent: "agent-support-1", Tool: "admin/promote_policy", Decision: "allow"},
		{Agent: "agent-support-1", Tool: "read_invoice", Decision: "allow"},
	})

	for _, e := range g.Edges {
		if e.To == "admin/mint" || e.To == "admin/promote_policy" {
			t.Fatalf("admin operation %q became an edge on the agent estate map", e.To)
		}
	}
	for _, n := range g.Nodes {
		if n.ID == "admin/mint" {
			t.Fatal("admin/mint listed as a tool agents reach")
		}
	}
	if len(g.Edges) != 1 || g.Edges[0].To != "read_invoice" {
		t.Fatalf("real tool traffic lost: %+v", g.Edges)
	}
}
