// Package segrec recommends a least-privilege segmentation policy from observed
// agent traffic. It turns "what the agents actually did" into "the narrowest
// zone rules that still allow it": the east-west edges their zones actually
// used, and the tools each zone actually called. An operator reviews the
// proposal and promotes it; nothing here changes enforcement.
//
// The recommendation is derived only from ALLOWED traffic, so it never
// proposes a rule that would permit something the gateway already blocks. Pure
// and deterministic: same flows in, same proposal out, sorted.
package segrec

import (
	"sort"

	"github.com/IntentGate-app/intentgate-gateway/internal/flowmap"
)

// Recommendation is a proposed least-privilege segmentation policy. Advisory
// only: a human reviews and promotes it.
type Recommendation struct {
	// AllowedEdges are the distinct directed zone-to-zone pairs observed in
	// allowed agent-to-agent traffic. Adding exactly these to the east-west
	// allowlist and default-denying the rest reproduces current behavior at
	// least privilege.
	AllowedEdges [][2]string `json:"allowed_edges"`
	// ZoneTools maps a zone to the sorted set of tools its agents actually
	// called (allowed). The proposed north-south scope per zone.
	ZoneTools map[string][]string `json:"zone_tools"`
	// IntraZoneObserved is true when at least one allowed agent-to-agent call
	// stayed within a single zone, i.e. allow_intra_zone would be needed to
	// keep current behavior.
	IntraZoneObserved bool `json:"intra_zone_observed"`
	// UnzonedAgents are agents seen in traffic with no zone in the directory.
	// They cannot be placed in a rule until they are zoned. Sorted, distinct.
	UnzonedAgents []string `json:"unzoned_agents"`
}

// Recommend builds a least-privilege proposal from an extracted flow graph.
// zoneOf resolves an agent id to its zone (""=unzoned).
func Recommend(graph flowmap.Graph, zoneOf func(string) string) Recommendation {
	edgeSet := map[[2]string]bool{}
	zoneTools := map[string]map[string]bool{}
	unzoned := map[string]bool{}
	intra := false

	zoneFor := func(agent string) string {
		z := zoneOf(agent)
		if z == "" {
			unzoned[agent] = true
		}
		return z
	}

	for _, e := range graph.Edges {
		// Only allowed traffic informs a least-privilege ALLOW rule.
		if e.Allow == 0 {
			continue
		}
		switch e.Kind {
		case flowmap.EdgeEastWest:
			cz := zoneFor(e.From)
			tz := zoneFor(e.To)
			if cz == "" || tz == "" {
				continue
			}
			if cz == tz {
				intra = true
			} else {
				edgeSet[[2]string{cz, tz}] = true
			}
		case flowmap.EdgeNorthSouth:
			cz := zoneFor(e.From)
			if cz == "" {
				continue
			}
			if zoneTools[cz] == nil {
				zoneTools[cz] = map[string]bool{}
			}
			zoneTools[cz][e.To] = true
		}
	}

	rec := Recommendation{
		AllowedEdges:      make([][2]string, 0, len(edgeSet)),
		ZoneTools:         make(map[string][]string, len(zoneTools)),
		IntraZoneObserved: intra,
		UnzonedAgents:     make([]string, 0, len(unzoned)),
	}
	for e := range edgeSet {
		rec.AllowedEdges = append(rec.AllowedEdges, e)
	}
	sort.Slice(rec.AllowedEdges, func(i, j int) bool {
		if rec.AllowedEdges[i][0] != rec.AllowedEdges[j][0] {
			return rec.AllowedEdges[i][0] < rec.AllowedEdges[j][0]
		}
		return rec.AllowedEdges[i][1] < rec.AllowedEdges[j][1]
	})
	for zone, tools := range zoneTools {
		list := make([]string, 0, len(tools))
		for t := range tools {
			list = append(list, t)
		}
		sort.Strings(list)
		rec.ZoneTools[zone] = list
	}
	for a := range unzoned {
		rec.UnzonedAgents = append(rec.UnzonedAgents, a)
	}
	sort.Strings(rec.UnzonedAgents)
	return rec
}
