// Package discovery aggregates observed authorization traffic into a
// passive inventory of the AI agents running against the gateway.
//
// It answers "what AI is running, and what does it touch" without any
// integration: every call an agent makes already flows through the
// gateway and lands in the audit log, so the set of distinct agents,
// the tools each one calls, and the risk signals those tools imply can
// be reconstructed from audit events alone.
//
// This is the OSS half of the discover → match → govern flow. The Pro
// console enriches each ObservedAgent with ownership and governance
// state; the gateway only reports the technical truth it observed.
package discovery

import (
	"sort"
	"strings"

	"github.com/IntentGate-app/intentgate-gateway/internal/audit"
)

// ObservedAgent is one agent the gateway has seen, aggregated across
// all of its audit events. It is the technical slice only — identity,
// what it called, how often, and the risk signals derived from the
// tools it touched. Ownership and governance are added downstream.
type ObservedAgent struct {
	AgentID      string   `json:"agent_id"`
	Tenant       string   `json:"tenant,omitempty"`
	Tools        []string `json:"tools"`
	RiskSignals  []string `json:"risk_signals"`
	Calls        int      `json:"calls"`
	Blocked      int      `json:"blocked"`
	FirstSeen    string   `json:"first_seen"`
	LastSeen     string   `json:"last_seen"`
	SessionCount int      `json:"session_count"`
}

// Risk signals derived from tool names. Deliberately conservative and
// transparent — a starting heuristic the Pro match engine and a human
// review refine. Mirrors the console's deriveRiskSignals.
const (
	SignalPayment        = "payment"
	SignalProductionData = "production-data"
	SignalOutbound       = "outbound"
	SignalRegulatedData  = "regulated-data"
	SignalUnknownID      = "unknown-identity"
)

var signalKeywords = []struct {
	signal   string
	keywords []string
}{
	{SignalPayment, []string{"payment", "billing", "invoice", "refund", "charge", "stripe", "paypal"}},
	{SignalProductionData, []string{"prod", "production", "prod-db", "prod_db"}},
	{SignalOutbound, []string{"email", "mail", "smtp", "sms", "slack", "teams", "webhook", "outbound", "send"}},
	{SignalRegulatedData, []string{"pii", "personal", "health", "medical", "hr", "payroll", "ssn", "gdpr", "financial"}},
}

// deriveRiskSignals returns the sorted, de-duplicated set of risk
// signals implied by an agent's identity and the tools it called.
func deriveRiskSignals(agentID string, tools []string) []string {
	hay := strings.ToLower(strings.Join(tools, " "))
	set := map[string]bool{}
	for _, sk := range signalKeywords {
		for _, kw := range sk.keywords {
			if strings.Contains(hay, kw) {
				set[sk.signal] = true
				break
			}
		}
	}
	id := strings.TrimSpace(strings.ToLower(agentID))
	if id == "" || strings.Contains(id, "unknown") || strings.Contains(id, "unidentified") {
		set[SignalUnknownID] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Aggregate folds a slice of audit events into the set of observed
// agents. Events are grouped by AgentID; an empty AgentID is bucketed
// under "unknown" so unidentified callers still surface (with the
// unknown-identity risk signal). The result is sorted with the most
// recently seen agents first.
func Aggregate(events []audit.Event) []ObservedAgent {
	type acc struct {
		tenant    string
		tools     map[string]bool
		sessions  map[string]bool
		calls     int
		blocked   int
		firstSeen string
		lastSeen  string
	}
	byAgent := map[string]*acc{}

	for _, e := range events {
		id := e.AgentID
		if strings.TrimSpace(id) == "" {
			id = "unknown"
		}
		a := byAgent[id]
		if a == nil {
			a = &acc{tools: map[string]bool{}, sessions: map[string]bool{}}
			byAgent[id] = a
		}
		if a.tenant == "" {
			a.tenant = e.Tenant
		}
		if e.Tool != "" {
			a.tools[e.Tool] = true
		}
		if e.SessionID != "" {
			a.sessions[e.SessionID] = true
		}
		a.calls++
		// A blocked decision is anything that did not allow the call.
		if e.Decision != "" && e.Decision != audit.DecisionAllow {
			a.blocked++
		}
		// Timestamps are RFC3339 strings; lexical compare is chronological.
		if a.firstSeen == "" || e.Timestamp < a.firstSeen {
			a.firstSeen = e.Timestamp
		}
		if e.Timestamp > a.lastSeen {
			a.lastSeen = e.Timestamp
		}
	}

	out := make([]ObservedAgent, 0, len(byAgent))
	for id, a := range byAgent {
		tools := make([]string, 0, len(a.tools))
		for t := range a.tools {
			tools = append(tools, t)
		}
		sort.Strings(tools)
		realID := id
		if id == "unknown" {
			realID = ""
		}
		out = append(out, ObservedAgent{
			AgentID:      realID,
			Tenant:       a.tenant,
			Tools:        tools,
			RiskSignals:  deriveRiskSignals(realID, tools),
			Calls:        a.calls,
			Blocked:      a.blocked,
			FirstSeen:    a.firstSeen,
			LastSeen:     a.lastSeen,
			SessionCount: len(a.sessions),
		})
	}

	// Most recently seen first; stable tiebreak on agent id.
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}
