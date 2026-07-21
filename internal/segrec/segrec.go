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
	// AllowedPairs are the distinct source-agent to destination-agent calls
	// observed in allowed traffic. This is the proposal that matters: it is
	// strictly tighter than a label rule, because it names both ends. Adopting
	// it grants nothing to an agent that has not already been calling.
	AllowedPairs [][2]string `json:"allowed_pairs"`
	// AllowedEdges are the distinct directed zone-to-zone pairs observed in
	// allowed agent-to-agent traffic. Adding exactly these to the east-west
	// allowlist and default-denying the rest reproduces current behavior at
	// least privilege.
	AllowedEdges [][2]string `json:"allowed_edges"`
	// GroupTools maps a group to the sorted set of tools its agents actually
	// called (allowed). The proposed agent-to-tool scope per group.
	//
	// Emitted under both names while consumers migrate. "zone_tools" is the
	// original spelling and is scheduled for removal; see the vocabulary note
	// on segmentationConfig.normalise in internal/handlers.
	GroupTools map[string][]string `json:"group_tools"`
	ZoneTools  map[string][]string `json:"zone_tools"`
	// IntraGroupObserved is true when at least one allowed agent-to-agent call
	// stayed within a single group, i.e. allow_intra_group would be needed to
	// keep current behavior.
	IntraGroupObserved bool `json:"intra_group_observed"`
	IntraZoneObserved  bool `json:"intra_zone_observed"`
	// UngroupedAgents are agents seen in traffic with no group in the
	// directory. They cannot be named in a group rule until they have one.
	// Sorted, distinct.
	UngroupedAgents []string `json:"ungrouped_agents"`
	UnzonedAgents   []string `json:"unzoned_agents"`
}

// Recommend builds a least-privilege proposal from an extracted flow graph.
// zoneOf resolves an agent id to its zone (""=unzoned).
func Recommend(graph flowmap.Graph, zoneOf func(string) string) Recommendation {
	edgeSet := map[[2]string]bool{}
	pairSet := map[[2]string]bool{}
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
			// The per-agent rule needs no zones at all, so it is recorded
			// before zone resolution and survives an unzoned agent.
			pairSet[[2]string{e.From, e.To}] = true
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
		AllowedPairs:      make([][2]string, 0, len(pairSet)),
		AllowedEdges:      make([][2]string, 0, len(edgeSet)),
		ZoneTools:         make(map[string][]string, len(zoneTools)),
		IntraZoneObserved: intra,
		UnzonedAgents:     make([]string, 0, len(unzoned)),
	}
	for p := range pairSet {
		rec.AllowedPairs = append(rec.AllowedPairs, p)
	}
	sort.Slice(rec.AllowedPairs, func(i, j int) bool {
		if rec.AllowedPairs[i][0] != rec.AllowedPairs[j][0] {
			return rec.AllowedPairs[i][0] < rec.AllowedPairs[j][0]
		}
		return rec.AllowedPairs[i][1] < rec.AllowedPairs[j][1]
	})
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
	// Mirror onto the supported names. Populating one set and copying is what
	// keeps the two spellings from drifting: there is exactly one place where
	// the values are computed.
	rec.GroupTools = rec.ZoneTools
	rec.IntraGroupObserved = rec.IntraZoneObserved
	rec.UngroupedAgents = rec.UnzonedAgents
	return rec
}
