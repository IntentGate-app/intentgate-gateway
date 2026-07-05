package segrec

import (
	"reflect"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/flowmap"
)

// zones places agents into a small directory for the tests.
func zones() func(string) string {
	m := map[string]string{
		"agent-procure": "procurement",
		"agent-finance": "finance",
		"agent-budget":  "finance",
		"agent-support": "support",
	}
	return func(a string) string { return m[a] }
}

// Allowed agent-to-agent traffic across zones becomes a recommended edge; a
// blocked edge does not.
func TestRecommend_EastWestEdgesFromAllowed(t *testing.T) {
	g := flowmap.Graph{Edges: []flowmap.Edge{
		{From: "agent-procure", To: "agent-finance", Kind: flowmap.EdgeEastWest, Allow: 3, Total: 3},
		{From: "agent-support", To: "agent-finance", Kind: flowmap.EdgeEastWest, Block: 2, Total: 2},
	}}
	rec := Recommend(g, zones())
	want := [][2]string{{"procurement", "finance"}}
	if !reflect.DeepEqual(rec.AllowedEdges, want) {
		t.Fatalf("allowed edges = %v, want %v", rec.AllowedEdges, want)
	}
}

// North-south allowed tools become the proposed per-zone scope, deduped and
// sorted; blocked tools are excluded.
func TestRecommend_ZoneToolsFromAllowed(t *testing.T) {
	g := flowmap.Graph{Edges: []flowmap.Edge{
		{From: "agent-finance", To: "read_invoice", Kind: flowmap.EdgeNorthSouth, Allow: 5, Total: 5},
		{From: "agent-budget", To: "read_ledger", Kind: flowmap.EdgeNorthSouth, Allow: 1, Total: 1},
		{From: "agent-finance", To: "transfer_funds", Kind: flowmap.EdgeNorthSouth, Block: 2, Total: 2},
	}}
	rec := Recommend(g, zones())
	want := []string{"read_invoice", "read_ledger"} // both finance agents, sorted, no blocked tool
	if !reflect.DeepEqual(rec.ZoneTools["finance"], want) {
		t.Fatalf("finance tools = %v, want %v", rec.ZoneTools["finance"], want)
	}
}

// Same-zone allowed traffic flags intra-zone.
func TestRecommend_IntraZoneObserved(t *testing.T) {
	g := flowmap.Graph{Edges: []flowmap.Edge{
		{From: "agent-finance", To: "agent-budget", Kind: flowmap.EdgeEastWest, Allow: 1, Total: 1},
	}}
	rec := Recommend(g, zones())
	if !rec.IntraZoneObserved {
		t.Fatal("expected intra-zone observed for finance->finance")
	}
	if len(rec.AllowedEdges) != 0 {
		t.Fatalf("intra-zone should not create a cross-zone edge, got %v", rec.AllowedEdges)
	}
}

// Agents with no zone are reported and cannot form a rule.
func TestRecommend_UnzonedAgents(t *testing.T) {
	g := flowmap.Graph{Edges: []flowmap.Edge{
		{From: "agent-ghost", To: "agent-finance", Kind: flowmap.EdgeEastWest, Allow: 1, Total: 1},
		{From: "agent-ghost", To: "read_invoice", Kind: flowmap.EdgeNorthSouth, Allow: 1, Total: 1},
	}}
	rec := Recommend(g, zones())
	if len(rec.UnzonedAgents) != 1 || rec.UnzonedAgents[0] != "agent-ghost" {
		t.Fatalf("unzoned = %v, want [agent-ghost]", rec.UnzonedAgents)
	}
	if len(rec.AllowedEdges) != 0 {
		t.Fatalf("unzoned caller should not form an edge, got %v", rec.AllowedEdges)
	}
	if _, ok := rec.ZoneTools[""]; ok {
		t.Fatal("unzoned caller should not create an empty-zone tool set")
	}
}

// Determinism: distinct edges come back sorted.
func TestRecommend_SortedEdges(t *testing.T) {
	g := flowmap.Graph{Edges: []flowmap.Edge{
		{From: "agent-support", To: "agent-finance", Kind: flowmap.EdgeEastWest, Allow: 1, Total: 1},
		{From: "agent-procure", To: "agent-finance", Kind: flowmap.EdgeEastWest, Allow: 1, Total: 1},
	}}
	rec := Recommend(g, zones())
	want := [][2]string{{"procurement", "finance"}, {"support", "finance"}}
	if !reflect.DeepEqual(rec.AllowedEdges, want) {
		t.Fatalf("edges = %v, want sorted %v", rec.AllowedEdges, want)
	}
}
