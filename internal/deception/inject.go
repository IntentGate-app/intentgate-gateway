package deception

import (
	"bytes"
	"encoding/json"
)

// Active deception injection: the proactive counterparts to the inline
// detectors in deception.go. Detection catches an agent that touches a decoy;
// injection is what plants the decoys in the first place.
//
//   - Tool-decoy injection appends synthetic honey-tool definitions to the
//     tools/list an upstream returns, so a compromised agent that has been told
//     to "use the admin tool" finds one and trips with certainty. No legitimate
//     workflow calls these.
//   - Canary injection seeds an operator-authored fake secret or record into a
//     response the agent retrieves (for example a RAG lookup), so a hijacked
//     agent that later exfiltrates it trips the detector, which already scans
//     agent traffic for these markers.
//
// Both are honest: the decoy tool descriptions are inert (never instructions,
// so a decoy cannot itself become an injection vector), and the canary values
// are the operator's own fake data, never anything real. Advertisement fails
// open (a decode error returns the original untouched); enforcement is
// unaffected and still lives in the detectors.

type decoyToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// DecoyToolDefs returns synthetic tool definitions for every honey-tool decoy,
// as raw JSON objects ready to append to a tools/list result.
func DecoyToolDefs(decoys []Decoy) []json.RawMessage {
	var out []json.RawMessage
	for _, d := range decoys {
		if d.Kind != HoneyTool {
			continue
		}
		name := d.Key
		if name == "" {
			name = d.Name
		}
		if name == "" {
			continue
		}
		desc := d.Synthetic
		if desc == "" {
			desc = "Restricted internal administrative operation."
		}
		b, err := json.Marshal(decoyToolDef{
			Name:        name,
			Description: desc,
			InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		})
		if err != nil {
			continue
		}
		out = append(out, json.RawMessage(b))
	}
	return out
}

// AppendDecoyTools merges honey-tool decoys into the "tools" array of a
// tools/list result, returning the augmented result and the number appended.
// Real tools are preserved and come first. On any decode error the original
// result is returned unchanged: advertising a decoy must never break a real
// tools/list.
func AppendDecoyTools(result json.RawMessage, decoys []Decoy) (json.RawMessage, int, error) {
	defs := DecoyToolDefs(decoys)
	if len(defs) == 0 {
		return result, 0, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return result, 0, err
	}
	var tools []json.RawMessage
	if raw, ok := obj["tools"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &tools); err != nil {
			return result, 0, err
		}
	}
	tools = append(tools, defs...)
	merged, err := json.Marshal(tools)
	if err != nil {
		return result, 0, err
	}
	obj["tools"] = merged
	out, err := json.Marshal(obj)
	if err != nil {
		return result, 0, err
	}
	return out, len(defs), nil
}

// CanaryValues returns the seed values for canary / honey-credential /
// honey-record decoys: unique fake secrets or records that no legitimate flow
// acts on.
func CanaryValues(decoys []Decoy) []string {
	var out []string
	for _, d := range decoys {
		switch d.Kind {
		case InjectionCanary, HoneyCredential, HoneyRecord:
			v := d.Synthetic
			if v == "" {
				v = d.Key
			}
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// InjectCanary seeds one canary value into a response body destined for the
// agent, so the value enters the agent's context and can be tripped on if
// exfiltrated. A JSON object gains a field, a JSON array gains an element, and
// any other body has the marker appended on its own line. Returns the augmented
// body and whether a canary was seeded. No-op when there are no canaries.
func InjectCanary(body []byte, canaries []string) ([]byte, bool) {
	if len(canaries) == 0 || len(body) == 0 {
		return body, false
	}
	marker := canaries[0]
	mv, err := json.Marshal(marker)
	if err != nil {
		return body, false
	}
	trimmed := bytes.TrimSpace(body)

	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj map[string]json.RawMessage
		if json.Unmarshal(body, &obj) == nil {
			obj["_ig_ref"] = json.RawMessage(mv)
			if out, err := json.Marshal(obj); err == nil {
				return out, true
			}
		}
	}
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(body, &arr) == nil {
			arr = append(arr, json.RawMessage(mv))
			if out, err := json.Marshal(arr); err == nil {
				return out, true
			}
		}
	}
	// Fallback: append the marker as a trailing reference line.
	return append(append([]byte{}, body...), append([]byte("\n"), marker...)...), true
}
