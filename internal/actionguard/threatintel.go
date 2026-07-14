// threatintel.go feeds known-bad indicators into the guard's plan-level
// correlation. It lets newly-seen attack patterns be caught without editing
// per-call policy: a curated or vendor-supplied feed of bad destinations, tool
// patterns, and action sequences is matched deterministically on every call.
//
// A hit on a denied destination or tool blocks outright; a hit on a known-bad
// action sequence (the current call completing a bad chain seen earlier in the
// session) escalates for human review.
package actionguard

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"github.com/IntentGate-app/intentgate-gateway/internal/actionir"
)

// ThreatFeed is a compiled set of known-bad indicators. Safe for concurrent
// use once built (it is read-only after construction).
type ThreatFeed struct {
	denyDest    map[string]bool
	denyTool    []*regexp.Regexp
	badSequence [][]actionir.Op
}

// NewThreatFeed builds a feed from explicit indicators. denyTools are compiled
// as regular expressions against the tool name.
func NewThreatFeed(denyDestinations, denyTools []string, badSequences [][]actionir.Op) (*ThreatFeed, error) {
	f := &ThreatFeed{denyDest: make(map[string]bool)}
	for _, d := range denyDestinations {
		if n := norm(d); n != "" {
			f.denyDest[n] = true
		}
	}
	for _, pat := range denyTools {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid deny_tool pattern %q: %w", pat, err)
		}
		f.denyTool = append(f.denyTool, re)
	}
	for _, seq := range badSequences {
		if len(seq) > 0 {
			f.badSequence = append(f.badSequence, seq)
		}
	}
	return f, nil
}

// match evaluates the current call against the feed. history is the prior
// session history (not yet including the current ir).
func (f *ThreatFeed) match(tool string, ir actionir.ActionIR, history []actionir.ActionIR) (Verdict, string, string, bool) {
	// Denied destination: block outright.
	if ir.Destination != "" && f.denyDest[norm(ir.Destination)] {
		return VerdictBlock,
			fmt.Sprintf("destination %q matches a known-bad threat-intel indicator", ir.Destination),
			"threat.deny_destination", true
	}
	// Denied tool pattern: block outright.
	for _, re := range f.denyTool {
		if re.MatchString(tool) {
			return VerdictBlock,
				fmt.Sprintf("tool %q matches a known-bad threat-intel pattern", tool),
				"threat.deny_tool", true
		}
	}
	// Known-bad ordered sequence completed by this call: escalate.
	if len(f.badSequence) > 0 {
		ops := make([]actionir.Op, 0, len(history)+1)
		for _, h := range history {
			ops = append(ops, h.Op)
		}
		ops = append(ops, ir.Op)
		for _, seq := range f.badSequence {
			if endsWithSeq(ops, seq) {
				return VerdictEscalate,
					"action completes a known-bad sequence from the threat-intel feed",
					"threat.bad_sequence", true
			}
		}
	}
	return VerdictAllow, "", "", false
}

// endsWithSeq reports whether ops ends with the contiguous ordered tail seq.
func endsWithSeq(ops, seq []actionir.Op) bool {
	if len(seq) == 0 || len(ops) < len(seq) {
		return false
	}
	off := len(ops) - len(seq)
	for i := range seq {
		if ops[off+i] != seq[i] {
			return false
		}
	}
	return true
}

// LoadThreatFeedFile reads a threat-intel JSON file of shape
//
//	{
//	  "deny_destinations": ["EVILCORP LTD"],
//	  "deny_tools": ["(?i)wire_transfer_external"],
//	  "bad_sequences": [["create","pay"], ["read","send"]]
//	}
//
// and returns a compiled ThreatFeed.
func LoadThreatFeedFile(path string) (*ThreatFeed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file struct {
		DenyDestinations []string   `json:"deny_destinations"`
		DenyTools        []string   `json:"deny_tools"`
		BadSequences     [][]string `json:"bad_sequences"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("invalid threat-intel feed: %w", err)
	}
	seqs := make([][]actionir.Op, 0, len(file.BadSequences))
	for _, s := range file.BadSequences {
		seq := make([]actionir.Op, 0, len(s))
		for _, op := range s {
			seq = append(seq, actionir.Op(op))
		}
		seqs = append(seqs, seq)
	}
	return NewThreatFeed(file.DenyDestinations, file.DenyTools, seqs)
}
