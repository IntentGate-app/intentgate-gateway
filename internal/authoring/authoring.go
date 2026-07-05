// Package authoring turns a plain-language description of a segmentation
// policy into a structured draft an operator can review, edit, and promote. It
// is deterministic and dependency-free: the same text always yields the same
// draft, and no model is involved. It is the reliable fallback behind the
// console's LLM-backed authoring assistant, and the whole thing on gateways
// without a model configured.
//
// The model never enforces anything: this produces a DRAFT that a human
// approves in the zone editor, after which the gateway enforces it
// deterministically. That guardrail is the point.
//
// Accepted lines (case-insensitive, one statement per line; blank lines and
// lines starting with # are ignored):
//
//	zone finance: agent-ledger, agent-ap        # put agents in a zone
//	agent-ledger is in finance                  # single membership
//	procurement may call finance                # allowed east-west edge
//	procurement -> finance                      # same, arrow form
//	allow intra-zone                            # same-zone calls allowed
//	finance may use read_invoice, record_ledger # north-south tool scope
//	finance tools: *                            # wildcard scope
//	finance in tenant acme                       # restrict a zone to tenants
//
// Anything it cannot parse is returned as a warning, never dropped silently.
package authoring

import (
	"regexp"
	"sort"
	"strings"
)

// Draft is the structured result of parsing a description. It maps cleanly onto
// the east-west and zone-scope config the gateway loads.
type Draft struct {
	Zones          map[string]string   `json:"zones"`
	AllowedEdges   [][2]string         `json:"allowed_edges"`
	AllowIntraZone bool                `json:"allow_intra_zone"`
	ZoneTools      map[string][]string `json:"zone_tools"`
	ZoneTenants    map[string][]string `json:"zone_tenants"`
	Warnings       []string            `json:"warnings"`
}

var (
	reZoneAssign = regexp.MustCompile(`(?i)^zone\s+([^\s:]+)\s*:\s*(.+)$`)
	reMembership = regexp.MustCompile(`(?i)^(\S+)\s+(?:is\s+in|in\s+zone|belongs\s+to)\s+(\S+)$`)
	reEdge       = regexp.MustCompile(`(?i)^(?:allow\s+)?(\S+)\s+(?:may\s+call|can\s+call|calls|->|→)\s+(\S+)$`)
	reTools      = regexp.MustCompile(`(?i)^(\S+)\s+(?:may\s+use|can\s+use|uses?|tools?\s*:)\s+(.+)$`)
	reTenants    = regexp.MustCompile(`(?i)^(\S+)\s+(?:tenants?\s*:|in\s+tenant)\s+(.+)$`)
	reIntra      = regexp.MustCompile(`(?i)(allow\s+)?intra[\s-]?zone|same[\s-]?zone`)
	reArrowEdge  = regexp.MustCompile(`^(\S+)\s*(?:->|→)\s*(\S+)$`)
)

// Parse converts a plain-language description into a Draft.
func Parse(text string) Draft {
	d := Draft{
		Zones:       map[string]string{},
		ZoneTools:   map[string][]string{},
		ZoneTenants: map[string][]string{},
	}
	edgeSet := map[[2]string]bool{}
	toolSet := map[string]map[string]bool{}
	tenantSet := map[string]map[string]bool{}

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)

		switch {
		case reIntra.MatchString(lower) && !reTools.MatchString(line) && !reEdge.MatchString(line):
			d.AllowIntraZone = true

		case reZoneAssign.MatchString(line):
			m := reZoneAssign.FindStringSubmatch(line)
			zone := strings.TrimSpace(m[1])
			for _, a := range splitList(m[2]) {
				d.Zones[a] = zone
			}

		case reMembership.MatchString(line):
			m := reMembership.FindStringSubmatch(line)
			d.Zones[m[1]] = m[2]

		case reEdge.MatchString(line):
			m := reEdge.FindStringSubmatch(line)
			edgeSet[[2]string{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true

		case reArrowEdge.MatchString(line):
			m := reArrowEdge.FindStringSubmatch(line)
			edgeSet[[2]string{strings.ToLower(m[1]), strings.ToLower(m[2])}] = true

		case reTenants.MatchString(line):
			m := reTenants.FindStringSubmatch(line)
			zone := m[1]
			if tenantSet[zone] == nil {
				tenantSet[zone] = map[string]bool{}
			}
			for _, t := range splitList(m[2]) {
				tenantSet[zone][t] = true
			}

		case reTools.MatchString(line):
			m := reTools.FindStringSubmatch(line)
			zone := m[1]
			if toolSet[zone] == nil {
				toolSet[zone] = map[string]bool{}
			}
			for _, t := range splitList(m[2]) {
				toolSet[zone][t] = true
			}

		default:
			d.Warnings = append(d.Warnings, "could not parse: "+line)
		}
	}

	for e := range edgeSet {
		d.AllowedEdges = append(d.AllowedEdges, e)
	}
	sort.Slice(d.AllowedEdges, func(i, j int) bool {
		if d.AllowedEdges[i][0] != d.AllowedEdges[j][0] {
			return d.AllowedEdges[i][0] < d.AllowedEdges[j][0]
		}
		return d.AllowedEdges[i][1] < d.AllowedEdges[j][1]
	})
	for zone, tools := range toolSet {
		d.ZoneTools[zone] = sortedKeys(tools)
	}
	for zone, tenants := range tenantSet {
		d.ZoneTenants[zone] = sortedKeys(tenants)
	}
	return d
}

// splitList splits "a, b c" on commas and whitespace into trimmed, non-empty
// tokens.
func splitList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
