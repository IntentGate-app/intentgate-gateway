package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IntentGate-app/intentgate-gateway/internal/eastwest"
)

// The segmentation config is written as a single document, so a PUT that omits
// a field would overwrite it with nothing. That is not a theoretical hazard:
// the console's Agent Groups page edits labels and tool scope, sends no
// agent-to-agent rules, and so erased every authorization in the estate on
// every save. It returned 200 each time.
//
// The rule these tests fix in place: an absent field is untouched, an explicit
// empty array clears.

func writeHandlerWithLivePairs(t *testing.T, pairs [][2]string) (http.Handler, string) {
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
			AllowedPairs:    pairs,
		}),
	}
	return NewAdminSegmentationWriteHandler(cfg), ewPath
}

func put(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/admin/segmentation",
		strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rr, req)
	return rr
}

func readPairs(t *testing.T, path string) [][2]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	// The file is the east-west document itself, not a wrapper.
	var doc struct {
		AllowedPairs [][2]string `json:"allowed_pairs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("written config is not valid JSON: %v\n%s", err, raw)
	}
	return doc.AllowedPairs
}

// The exact shape the console's Agent Groups page sends: labels and scope, no
// agent-to-agent rules. Every existing rule must survive it.
func TestWriteWithoutPairsPreservesThem(t *testing.T) {
	live := [][2]string{
		{"agent-procure-1", "agent-finance-1"},
		{"agent-procure-2", "agent-finance-1"},
		{"agent-procure-3", "agent-finance-1"},
	}
	h, path := writeHandlerWithLivePairs(t, live)

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "allow_intra_group": false,
	    "groups": {"agent-finance-1": "finance"},
	    "allowed_edges": []
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := readPairs(t, path)
	if len(got) != len(live) {
		t.Fatalf("a save that never mentioned agent-to-agent rules changed them: "+
			"got %d, want %d\n%v", len(got), len(live), got)
	}
	for i, p := range live {
		if got[i] != p {
			t.Errorf("pair %d altered: got %v, want %v", i, got[i], p)
		}
	}
}

// Clearing must stay possible, or there is no way to revoke every rule at once.
// An explicit empty array is the operator saying so.
func TestWriteWithExplicitEmptyPairsClearsThem(t *testing.T) {
	h, path := writeHandlerWithLivePairs(t, [][2]string{
		{"agent-procure-1", "agent-finance-1"},
	})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "groups": {"agent-finance-1": "finance"},
	    "allowed_pairs": []
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if got := readPairs(t, path); len(got) != 0 {
		t.Fatalf("an explicit [] should clear the rules, got %v", got)
	}
}

// A PUT that does name rules replaces them, which is what the Agent
// Authorization page relies on.
func TestWriteWithPairsReplacesThem(t *testing.T) {
	h, path := writeHandlerWithLivePairs(t, [][2]string{
		{"agent-procure-1", "agent-finance-1"},
	})

	rr := put(t, h, `{
	  "east_west": {
	    "agent_tool_prefix": "agent:",
	    "groups": {"agent-finance-1": "finance"},
	    "allowed_pairs": [["agent-support-1", "agent-finance-1"]]
	  },
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	got := readPairs(t, path)
	if len(got) != 1 || got[0] != [2]string{"agent-support-1", "agent-finance-1"} {
		t.Fatalf("submitted rules were not written: %v", got)
	}
}

// Group labels are the other field a partial save could wipe. Same rule.
func TestWriteWithoutGroupsPreservesThem(t *testing.T) {
	h, path := writeHandlerWithLivePairs(t, nil)

	rr := put(t, h, `{
	  "east_west": {"agent_tool_prefix": "agent:", "allowed_pairs": []},
	  "tool_scope": {"scopes": {}}
	}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	var doc struct {
		Groups map[string]string `json:"groups"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("written config is not valid JSON: %v", err)
	}
	if doc.Groups["agent-finance-1"] != "finance" {
		t.Fatalf("a save that never mentioned labels dropped them: %v", doc.Groups)
	}
}
