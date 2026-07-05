// Package flowmap extracts an agent estate topology from observed gateway
// calls: which agent reaches which tools (north-south) and which agents reach
// which other agents (east-west), with per-edge allow/block/escalate counts.
//
// This is the visibility half of agent microsegmentation. The enforcement
// packages (eastwest, zonescope, capability) decide each call; this package
// summarizes what actually happened, from the audit stream the gateway already
// records, into a graph the console can draw. No new instrumentation is
// needed: every field it reads (agent, tool, tenant, decision) is already on
// each audit event.
//
// Extract is a pure, deterministic function over a slice of observed calls, so
// it is trivially testable and free of I/O. The wiring layer feeds it audit
// events; this package never touches a store.
package flowmap

import "sort"

// Call is one observed gateway call, the minimal shape the extractor needs.
// The wiring layer maps an audit event onto this.
type Call struct {
	Agent    string
	Tool     string
	Tenant   string
	Decision string // "allow", "block", or "escalate"
}

// Config configures edge extraction.
type Config struct {
	// AgentToolPrefix marks a tool as an agent-to-agent target, for example
	// "agent:". A call to "<prefix><id>" becomes a caller-to-callee edge
	// between two agent nodes. Empty disables east-west edge detection, so
	// every call is treated as agent-to-tool. This should match the
	// east-west guard's prefix so the map and the enforcement agree.
	AgentToolPrefix string
}

// NodeKind classifies a node in the graph.
type NodeKind string

const (
	NodeAgent NodeKind = "agent"
	NodeTool  NodeKind = "tool"
)

// Node is a vertex: an agent or a tool.
type Node struct {
	ID   string   `json:"id"`
	Kind NodeKind `json:"kind"`
}

// EdgeKind classifies an edge.
type EdgeKind string

const (
	EdgeNorthSouth EdgeKind = "north_south" // agent -> tool
	EdgeEastWest   EdgeKind = "east_west"   // agent -> agent
)

// Edge is an aggregated directed edge with decision counts.
type Edge struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Kind     EdgeKind `json:"kind"`
	Allow    int      `json:"allow"`
	Block    int      `json:"block"`
	Escalate int      `json:"escalate"`
	Total    int      `json:"total"`
	// Tenants is the distinct set of tenants seen on this edge, sorted.
	Tenants []string `json:"tenants,omitempty"`
}

// Graph is the extracted topology, with nodes and edges in a stable order.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// agentTarget reports whether tool is an agent-to-agent target and, when it
// is, the callee agent id. A tool that starts with the prefix but has nothing
// after it (a bare prefix) is still an agent target, but malformed: it returns
// ("", true) so the caller can skip it rather than mistake it for a tool named
// after the prefix.
func (c Config) agentTarget(tool string) (callee string, isAgent bool) {
	p := c.AgentToolPrefix
	if p == "" || len(tool) < len(p) || tool[:len(p)] != p {
		return "", false
	}
	return tool[len(p):], true
}

// Extract builds the flow graph from observed calls. Deterministic: nodes and
// edges come back sorted, and decision counts aggregate per directed edge.
// Calls with an empty Agent or Tool, or an east-west call with a bare prefix,
// are skipped.
func Extract(cfg Config, calls []Call) Graph {
	kinds := map[string]NodeKind{}
	setAgent := func(id string) {
		kinds[id] = NodeAgent // agent role always wins
	}
	setTool := func(id string) {
		if _, ok := kinds[id]; !ok {
			kinds[id] = NodeTool
		}
	}

	type key struct{ from, to string }
	edges := map[key]*Edge{}
	tenantSeen := map[key]map[string]bool{}

	for _, c := range calls {
		if c.Agent == "" || c.Tool == "" {
			continue
		}
		to := c.Tool
		kind := EdgeNorthSouth
		if callee, isAgent := cfg.agentTarget(c.Tool); isAgent {
			if callee == "" {
				continue // bare prefix: malformed east-west call
			}
			to = callee
			kind = EdgeEastWest
		}

		setAgent(c.Agent)
		if kind == EdgeEastWest {
			setAgent(to)
		} else {
			setTool(to)
		}

		k := key{c.Agent, to}
		e := edges[k]
		if e == nil {
			e = &Edge{From: c.Agent, To: to, Kind: kind}
			edges[k] = e
			tenantSeen[k] = map[string]bool{}
		}
		switch c.Decision {
		case "allow":
			e.Allow++
		case "block":
			e.Block++
		case "escalate":
			e.Escalate++
		}
		e.Total++
		if c.Tenant != "" && !tenantSeen[k][c.Tenant] {
			tenantSeen[k][c.Tenant] = true
			e.Tenants = append(e.Tenants, c.Tenant)
		}
	}

	g := Graph{
		Nodes: make([]Node, 0, len(kinds)),
		Edges: make([]Edge, 0, len(edges)),
	}
	for id, k := range kinds {
		g.Nodes = append(g.Nodes, Node{ID: id, Kind: k})
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	for k := range edges {
		e := edges[k]
		sort.Strings(e.Tenants)
		g.Edges = append(g.Edges, *e)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}
