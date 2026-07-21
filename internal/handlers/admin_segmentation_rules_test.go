package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
)

// Rules are AllowedPairs with the reasoning attached, and they are carried
// through the same whole-document write. So they inherit the same failure mode
// and need the same protection: an absent field is untouched, an explicit empty
// array clears. These tests are the ones that did not exist when the bare-pairs
// version of this handler deleted every authorization in the lab.
//
// The stakes differ from pairs in one way worth stating. Losing a pair revokes
// access, which fails loudly the moment an agent is denied. Losing a rule while
// keeping its pair revokes nothing and breaks silently: the call still works,
// but the purpose, owner, approver and expiry are gone, and an expiry the
// gateway is no longer enforcing looks identical to one that has not arrived.

func writeHandlerWithLiveRules(t *testing.T, rules []eastwest.Rule) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	ewPath := filepath.Join(dir, "eastwest.json")
	cfg := AdminConfig{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:         "secret",
		EastWestConfigPath: ewPath,
		EastWest: eastwest.New(eastwest.Config{
			AgentToolPrefix: "agent:",
			Zones:           map[string]string{"agent-finance-1": "finance"},
			Rules:           rules,
		}),
	}
	return NewAdminSegmentationWriteHandler(cfg), ewPath
}

func readRules(t *testing.T, path string) []eastwest.Rule {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	var doc struct {
		Rules []eastwest.Rule `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("written config is not valid JSON: %v\n%s", err, raw)
	}
	return doc.Rules
}

func sampleRule() eastwest.Rule {
	return eastwest.Rule{
		From:       "agent-procure-1",
		To:         "agent-finance-1",
		Purpose:    "confirm invoice totals before raising a PO",
		Owner:      "procurement-platform",
		ApprovedBy: "risk@example.com",
		ApprovedAt: time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second),
		ExpiresAt:  time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second),
	}
}

// The shape the Agent Groups page sends: labels and tool scope, nothing about
// agent-to-agent permissions. Every governance record must survive it intact.
func TestWriteWithoutRulesPreservesThem(t *testing.T) {
	live := sampleRule()
	h, path := writeHandlerWithLiveRules(t, []eastwest.Rule{live})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "groups": {"agent-finance-1": "finance"},
	    "allowed_edges": []
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := readRules(t, path)
	if len(got) != 1 {
		t.Fatalf("a save that never mentioned rules changed them: got %d, want 1\n%v",
			len(got), got)
	}
	// Field by field, because a rule that survives as a bare from/to has lost
	// exactly the thing that makes it a rule rather than a pair.
	if got[0].From != live.From || got[0].To != live.To {
		t.Errorf("endpoints altered: got %s -> %s", got[0].From, got[0].To)
	}
	if got[0].Purpose != live.Purpose {
		t.Errorf("purpose lost: %q", got[0].Purpose)
	}
	if got[0].Owner != live.Owner {
		t.Errorf("owner lost: %q", got[0].Owner)
	}
	if got[0].ApprovedBy != live.ApprovedBy {
		t.Errorf("approver lost: %q", got[0].ApprovedBy)
	}
	if !got[0].ApprovedAt.Equal(live.ApprovedAt) {
		t.Errorf("approval date lost: got %v, want %v", got[0].ApprovedAt, live.ApprovedAt)
	}
	// The enforced field. A dropped expiry turns a permission that was meant to
	// lapse in three days into one that never lapses, and nothing reports it.
	if !got[0].ExpiresAt.Equal(live.ExpiresAt) {
		t.Errorf("expiry lost: got %v, want %v", got[0].ExpiresAt, live.ExpiresAt)
	}
}

// Revoking everything at once has to stay possible. An explicit [] is the
// operator saying so, and must not be confused with the field being absent.
func TestWriteWithExplicitEmptyRulesClearsThem(t *testing.T) {
	h, path := writeHandlerWithLiveRules(t, []eastwest.Rule{sampleRule()})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "groups": {"agent-finance-1": "finance"},
	    "rules": []
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if got := readRules(t, path); len(got) != 0 {
		t.Fatalf("an explicit [] should clear the rules, got %v", got)
	}
}

// A PUT that does name rules replaces them, which is what the Agent
// Authorization page will rely on once it is rebuilt.
func TestWriteWithRulesReplacesThem(t *testing.T) {
	h, path := writeHandlerWithLiveRules(t, []eastwest.Rule{sampleRule()})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "groups": {"agent-finance-1": "finance"},
	    "rules": [{
	      "from": "agent-support-1",
	      "to": "agent-finance-1",
	      "purpose": "look up an invoice on a customer call",
	      "owner": "support-platform",
	      "approved_by": "risk@example.com"
	    }]
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := readRules(t, path)
	if len(got) != 1 || got[0].From != "agent-support-1" {
		t.Fatalf("submitted rules were not written: %v", got)
	}
	if got[0].Purpose == "" || got[0].Owner == "" || got[0].ApprovedBy == "" {
		t.Errorf("governance fields dropped on write: %+v", got[0])
	}
}

// Rules and pairs are separate fields evaluated together, so a save that names
// one must not disturb the other. Otherwise editing bare pairs silently strips
// every justification, which is the same bug wearing a different field name.
func TestWritingPairsDoesNotDisturbRules(t *testing.T) {
	dir := t.TempDir()
	ewPath := filepath.Join(dir, "eastwest.json")
	h := NewAdminSegmentationWriteHandler(AdminConfig{
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken:         "secret",
		EastWestConfigPath: ewPath,
		EastWest: eastwest.New(eastwest.Config{
			AgentToolPrefix: "agent:",
			AllowedPairs:    [][2]string{{"agent-a", "agent-b"}},
			Rules:           []eastwest.Rule{sampleRule()},
		}),
	})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "allowed_pairs": [["agent-c", "agent-d"]]
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if got := readRules(t, ewPath); len(got) != 1 || got[0].Purpose == "" {
		t.Fatalf("editing pairs discarded the governance records: %v", got)
	}
	if got := readPairs(t, ewPath); len(got) != 1 || got[0] != [2]string{"agent-c", "agent-d"} {
		t.Fatalf("pairs were not written: %v", got)
	}
}

// The read side. The console saves back what this returns, so a rule the GET
// omits is a rule the next save deletes. That is the loop the whole absent-vs-
// empty contract depends on, and it is only sound if both ends hold.
func TestReadReportsRules(t *testing.T) {
	live := sampleRule()
	h := NewAdminSegmentationHandler(AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		EastWest: eastwest.New(eastwest.Config{
			AgentToolPrefix: "agent:",
			Rules:           []eastwest.Rule{live},
		}),
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/segmentation", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var doc struct {
		EastWest struct {
			Rules []eastwest.Rule `json:"rules"`
		} `json:"east_west"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(doc.EastWest.Rules) != 1 {
		t.Fatalf("the gateway did not report its governance records: %v", rr.Body.String())
	}
	if doc.EastWest.Rules[0].Purpose != live.Purpose {
		t.Errorf("purpose not reported: %q", doc.EastWest.Rules[0].Purpose)
	}
	if !doc.EastWest.Rules[0].ExpiresAt.Equal(live.ExpiresAt) {
		t.Errorf("an enforced expiry was not reported: got %v, want %v",
			doc.EastWest.Rules[0].ExpiresAt, live.ExpiresAt)
	}
}

// A gateway holding no rules must say "none", not "unknown". `rules: null`
// reads back as an absent field, and an absent field means preserve, so a
// console that round-trips it could never clear the last rule.
func TestReadReportsEmptyRulesAsArrayNotNull(t *testing.T) {
	h := NewAdminSegmentationHandler(AdminConfig{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		AdminToken: "secret",
		EastWest:   eastwest.New(eastwest.Config{AgentToolPrefix: "agent:"}),
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/segmentation", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)

	var doc struct {
		EastWest map[string]json.RawMessage `json:"east_west"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	raw, ok := doc.EastWest["rules"]
	if !ok {
		t.Fatal("rules field absent from the response entirely")
	}
	if string(raw) == "null" {
		t.Error("empty ruleset reported as null, which the write path reads as 'preserve'")
	}
}
