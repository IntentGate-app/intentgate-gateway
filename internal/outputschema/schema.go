// Package outputschema enforces declared response shapes on tool
// responses returned by the upstream toolserver before they reach
// the agent.
//
// Threat closed (OWASP LLM05 — Improper Output Handling):
// an upstream tool legitimately returns a structured response but
// includes fields the schema didn't declare, types it didn't promise,
// or values outside an enum. Without enforcement, agents see the
// extra/wrong fields and propagate them — exfiltrating sensitive
// data, taking decisions on values they shouldn't trust, or breaking
// downstream tools that expected the declared shape.
//
// The package is intentionally a strict subset of JSON Schema —
// enough for the practical "declare what each tool returns" story
// without dragging in a heavyweight validator. Supported:
//
//   - type: "object" | "array" | "string" | "number" | "integer" |
//     "boolean" | "null"
//   - properties: per-field nested schemas
//   - required: list of property names that must be present
//   - additionalProperties: false → strip / block undeclared fields
//   - items: schema for array elements
//   - enum: list of allowed values (strings, numbers, booleans)
//
// Actions are the same vocabulary as the PII filter:
//
//   - allow  — log only, pass the response through
//   - strip  — remove undeclared fields, coerce-or-drop wrong-type
//     scalars; pass the cleaned response through
//   - block  — refuse the response, return CodeOutputSchemaViolation
//     (-32016) to the caller
//
// Schemas are declared per-tool in a JSON file pointed at by
// INTENTGATE_OUTPUT_SCHEMAS_PATH, or overridden per-request via Rego
// (`output_schema` field on the policy decision). When no schema is
// declared for a tool, the check is a no-op for that call.
package outputschema

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Action describes what the filter should do when a tool response
// violates its declared schema.
type Action string

const (
	// ActionAllow logs the violation but passes the response through
	// unchanged. Useful during a rollout when operators want telemetry
	// before flipping to strip/block.
	ActionAllow Action = "allow"
	// ActionStrip removes undeclared fields and coerces/drops scalars
	// whose type doesn't match. The cleaned response is forwarded.
	// Default action — closest to "principle of least surprise" for
	// most schemas.
	ActionStrip Action = "strip"
	// ActionBlock refuses the response entirely and returns
	// CodeOutputSchemaViolation (-32016) to the caller. Per-class
	// match counts go into the audit row; matched values never leave
	// the gateway.
	ActionBlock Action = "block"
)

// ParseAction returns the Action constant for the given string,
// defaulting to ActionStrip on empty input and erroring on unknown
// values.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return ActionStrip, nil
	case "allow":
		return ActionAllow, nil
	case "strip":
		return ActionStrip, nil
	case "block":
		return ActionBlock, nil
	default:
		return "", fmt.Errorf("outputschema: unknown action %q (want allow|strip|block)", s)
	}
}

// Schema is the in-memory representation of a per-tool output schema.
// Build one with [Parse]; evaluate it against a response with
// [Schema.Validate].
type Schema struct {
	// Type is the JSON-Schema-style type marker. One of: object,
	// array, string, number, integer, boolean, null, or empty (any).
	Type string

	// Properties maps field name → sub-schema for object types.
	Properties map[string]*Schema

	// Required lists property names that must be present when Type
	// is "object". Missing required fields are always treated as
	// violations regardless of Action.
	Required []string

	// AdditionalProperties controls behaviour for fields not declared
	// in Properties. When false (the default), extras are violations
	// — stripped (action=strip) or block (action=block). When true,
	// extras pass through.
	AdditionalProperties bool

	// Items is the per-element schema when Type is "array". When nil,
	// array elements are not introspected (just shape-checked).
	Items *Schema

	// Enum is the list of allowed scalar values. Compared with
	// reflect.DeepEqual after json.Unmarshal so types must match
	// exactly (number 1 ≠ string "1").
	Enum []any
}

// schemaJSON is the on-disk shape Parse reads. We keep the Go struct
// (Schema) and the JSON struct (schemaJSON) separate so a future
// schema-language change can stage compatibility shims without
// breaking the runtime type.
type schemaJSON struct {
	Type                 string                 `json:"type,omitempty"`
	Properties           map[string]*schemaJSON `json:"properties,omitempty"`
	Required             []string               `json:"required,omitempty"`
	AdditionalProperties *bool                  `json:"additionalProperties,omitempty"`
	Items                *schemaJSON            `json:"items,omitempty"`
	Enum                 []any                  `json:"enum,omitempty"`
}

// Parse decodes a JSON-encoded schema document and returns the
// runtime form. Returns an error if the document is malformed or
// declares an unknown type.
func Parse(raw []byte) (*Schema, error) {
	var j schemaJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("outputschema: parse: %w", err)
	}
	return fromJSON(&j)
}

func fromJSON(j *schemaJSON) (*Schema, error) {
	if j == nil {
		return nil, nil
	}
	if err := validateTypeName(j.Type); err != nil {
		return nil, err
	}
	s := &Schema{
		Type:                 j.Type,
		Required:             append([]string(nil), j.Required...),
		AdditionalProperties: false, // strict default
		Enum:                 append([]any(nil), j.Enum...),
	}
	if j.AdditionalProperties != nil {
		s.AdditionalProperties = *j.AdditionalProperties
	}
	if len(j.Properties) > 0 {
		s.Properties = make(map[string]*Schema, len(j.Properties))
		for k, v := range j.Properties {
			sub, err := fromJSON(v)
			if err != nil {
				return nil, fmt.Errorf("outputschema: properties[%q]: %w", k, err)
			}
			s.Properties[k] = sub
		}
	}
	if j.Items != nil {
		sub, err := fromJSON(j.Items)
		if err != nil {
			return nil, fmt.Errorf("outputschema: items: %w", err)
		}
		s.Items = sub
	}
	return s, nil
}

func validateTypeName(t string) error {
	switch t {
	case "", "object", "array", "string", "number", "integer", "boolean", "null":
		return nil
	default:
		return fmt.Errorf("outputschema: unknown type %q", t)
	}
}

// Violation describes one rule failure surfaced by Validate.
// Pointer is a JSON-pointer-style path (e.g. "/customer/email") so an
// operator reading the audit row knows exactly where the response
// drifted from spec.
type Violation struct {
	Pointer string // JSON-pointer-style path; "" for the root
	Kind    string // missing_required | extra_property | wrong_type | enum_violation | malformed
	Detail  string // human-readable explanation
}

// Result is what Validate returns.
type Result struct {
	// Violations is the full list of rule failures, in the order
	// encountered during the depth-first traversal. Empty when the
	// response conforms.
	Violations []Violation

	// Counts is per-Kind aggregation, suitable for an audit row
	// (the audit chain stores counts only, never matched values).
	Counts map[string]int

	// Stripped, when non-empty, is the response with undeclared
	// fields and wrong-type scalars removed. Always populated; equals
	// the original input when there were no violations.
	Stripped json.RawMessage
}

// Validate evaluates the response against the schema and returns a
// Result. Validate never errors — schema authors who hand it
// non-JSON, malformed input get one synthetic Violation describing
// the parse failure.
//
// Stripped is always populated. When there are no violations it
// equals the original input. When there are violations and the
// caller chose ActionStrip, Stripped is safe to forward.
func (s *Schema) Validate(raw json.RawMessage) Result {
	if s == nil {
		// No schema declared → caller treats this as a no-op.
		return Result{Stripped: raw, Counts: map[string]int{}}
	}
	if len(raw) == 0 {
		return Result{
			Violations: []Violation{{Kind: "malformed", Detail: "empty response body"}},
			Counts:     map[string]int{"malformed": 1},
		}
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return Result{
			Violations: []Violation{{Kind: "malformed", Detail: err.Error()}},
			Counts:     map[string]int{"malformed": 1},
		}
	}
	r := Result{Counts: map[string]int{}}
	cleaned := s.walk(node, "", &r)
	out, err := json.Marshal(cleaned)
	if err != nil {
		r.add("", "malformed", "could not re-encode stripped response: "+err.Error())
		r.Stripped = raw
		return r
	}
	r.Stripped = out
	return r
}

// walk validates one node against the schema and returns the cleaned
// version (with extra/wrong-type fields removed for ActionStrip's
// benefit). Violations accumulate on the Result pointer.
func (s *Schema) walk(node any, ptr string, r *Result) any {
	if s == nil {
		return node
	}
	// Empty schema type = any. Still respect enum.
	if s.Type == "" {
		return s.checkEnum(node, ptr, r)
	}

	switch s.Type {
	case "object":
		return s.walkObject(node, ptr, r)
	case "array":
		return s.walkArray(node, ptr, r)
	case "string":
		if v, ok := node.(string); ok {
			return s.checkEnum(v, ptr, r)
		}
		r.add(ptr, "wrong_type", fmt.Sprintf("expected string, got %T", node))
		return nil
	case "number":
		switch v := node.(type) {
		case float64:
			return s.checkEnum(v, ptr, r)
		case json.Number:
			return s.checkEnum(v, ptr, r)
		}
		r.add(ptr, "wrong_type", fmt.Sprintf("expected number, got %T", node))
		return nil
	case "integer":
		if v, ok := node.(float64); ok && v == float64(int64(v)) {
			return s.checkEnum(int64(v), ptr, r)
		}
		r.add(ptr, "wrong_type", fmt.Sprintf("expected integer, got %T", node))
		return nil
	case "boolean":
		if v, ok := node.(bool); ok {
			return s.checkEnum(v, ptr, r)
		}
		r.add(ptr, "wrong_type", fmt.Sprintf("expected boolean, got %T", node))
		return nil
	case "null":
		if node == nil {
			return nil
		}
		r.add(ptr, "wrong_type", fmt.Sprintf("expected null, got %T", node))
		return nil
	}
	return node
}

func (s *Schema) walkObject(node any, ptr string, r *Result) any {
	obj, ok := node.(map[string]any)
	if !ok {
		r.add(ptr, "wrong_type", fmt.Sprintf("expected object, got %T", node))
		return nil
	}
	out := make(map[string]any, len(obj))

	// Required.
	for _, name := range s.Required {
		if _, present := obj[name]; !present {
			r.add(joinPtr(ptr, name), "missing_required", "required property is absent")
		}
	}

	// Properties + additionalProperties.
	for k, v := range obj {
		sub, declared := s.Properties[k]
		childPtr := joinPtr(ptr, k)
		if declared {
			out[k] = sub.walk(v, childPtr, r)
			continue
		}
		if s.AdditionalProperties {
			out[k] = v
			continue
		}
		r.add(childPtr, "extra_property", "property not declared in schema")
		// Strip: omit from out.
	}
	return out
}

func (s *Schema) walkArray(node any, ptr string, r *Result) any {
	arr, ok := node.([]any)
	if !ok {
		r.add(ptr, "wrong_type", fmt.Sprintf("expected array, got %T", node))
		return nil
	}
	if s.Items == nil {
		return arr
	}
	out := make([]any, 0, len(arr))
	for i, v := range arr {
		childPtr := fmt.Sprintf("%s/%d", ptr, i)
		cleaned := s.Items.walk(v, childPtr, r)
		if cleaned != nil {
			out = append(out, cleaned)
		}
	}
	return out
}

func (s *Schema) checkEnum(v any, ptr string, r *Result) any {
	if len(s.Enum) == 0 {
		return v
	}
	for _, allowed := range s.Enum {
		if jsonEqual(allowed, v) {
			return v
		}
	}
	r.add(ptr, "enum_violation", fmt.Sprintf("value not in declared enum: %v", v))
	return nil
}

// jsonEqual compares two values that came out of json.Unmarshal.
// Necessary because Unmarshal turns all numbers into float64 (or
// json.Number when configured), so a literal-int "1" in the schema
// won't structurally equal the float64(1) in the response.
func jsonEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == b
	}
	af, aok := toFloat(a)
	bf, bok := toFloat(b)
	if aok && bok {
		return af == bf
	}
	return a == b
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func joinPtr(parent, key string) string {
	// JSON pointer: ~ and / are escaped; keep it simple — we never
	// surface pointers in customer-facing text, only audit rows.
	return parent + "/" + escapePtrSegment(key)
}

func escapePtrSegment(s string) string {
	s = strings.ReplaceAll(s, "~", "~0")
	s = strings.ReplaceAll(s, "/", "~1")
	return s
}

func (r *Result) add(ptr, kind, detail string) {
	r.Violations = append(r.Violations, Violation{Pointer: ptr, Kind: kind, Detail: detail})
	r.Counts[kind]++
}

// CountsByKind returns per-violation-kind counts. Convenience for
// audit-row emission (counts only, never matched values).
func (r Result) CountsByKind() map[string]int {
	out := make(map[string]int, len(r.Counts))
	for k, v := range r.Counts {
		out[k] = v
	}
	return out
}

// HasViolations is true when the schema check found at least one
// violation.
func (r Result) HasViolations() bool {
	return len(r.Violations) > 0
}

// Registry is a tool-name → Schema map plus a default Action. Built
// once at gateway startup from INTENTGATE_OUTPUT_SCHEMAS_PATH (or
// equivalent) and consulted on every tool response.
type Registry struct {
	schemas       map[string]*Schema
	defaultAction Action
	// PerToolAction lets operators set, e.g., action=block on the
	// most sensitive tools and action=strip everywhere else. Falls
	// back to defaultAction when a tool isn't listed.
	perToolAction map[string]Action
}

// NewRegistry builds a Registry. defaultAction empty falls back to
// ActionStrip. schemas may be nil (the Registry then no-ops on every
// tool until LoadJSON is called).
func NewRegistry(defaultAction Action) *Registry {
	if defaultAction == "" {
		defaultAction = ActionStrip
	}
	return &Registry{
		schemas:       map[string]*Schema{},
		defaultAction: defaultAction,
		perToolAction: map[string]Action{},
	}
}

// AddTool registers (or replaces) the schema for one tool name.
func (r *Registry) AddTool(name string, schema *Schema) {
	if r == nil {
		return
	}
	r.schemas[name] = schema
}

// SetToolAction overrides the per-tool action. Pass "" to clear.
func (r *Registry) SetToolAction(name string, action Action) {
	if r == nil {
		return
	}
	if action == "" {
		delete(r.perToolAction, name)
		return
	}
	r.perToolAction[name] = action
}

// Lookup returns the schema and effective action for a tool. ok is
// false when the tool has no declared schema (caller should no-op).
func (r *Registry) Lookup(tool string) (schema *Schema, action Action, ok bool) {
	if r == nil {
		return nil, "", false
	}
	s, ok := r.schemas[tool]
	if !ok {
		return nil, "", false
	}
	a, has := r.perToolAction[tool]
	if !has {
		a = r.defaultAction
	}
	return s, a, true
}

// ToolNames returns the registered tool names, sorted for stable
// admin output. (Map iteration order is randomized — never expose it
// to operators.)
func (r *Registry) ToolNames() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.schemas))
	for k := range r.schemas {
		out = append(out, k)
	}
	// Sort manually rather than pulling in sort just for this — small N.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// LoadJSON parses a config document of the form
//
//	{
//	  "default_action": "strip",
//	  "tools": {
//	    "read_customer": {
//	      "schema": { ...JSON Schema subset... },
//	      "action": "block"
//	    },
//	    ...
//	  }
//	}
//
// and merges its entries into the registry. Existing entries are
// overwritten by matching ones in the document.
func (r *Registry) LoadJSON(raw []byte) error {
	if r == nil {
		return errors.New("outputschema: LoadJSON on nil registry")
	}
	if len(raw) == 0 {
		return nil
	}
	var doc struct {
		DefaultAction string `json:"default_action"`
		Tools         map[string]struct {
			Schema json.RawMessage `json:"schema"`
			Action string          `json:"action"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("outputschema: LoadJSON: %w", err)
	}
	if doc.DefaultAction != "" {
		act, err := ParseAction(doc.DefaultAction)
		if err != nil {
			return err
		}
		r.defaultAction = act
	}
	for name, entry := range doc.Tools {
		s, err := Parse(entry.Schema)
		if err != nil {
			return fmt.Errorf("outputschema: tool %q: %w", name, err)
		}
		r.schemas[name] = s
		if entry.Action != "" {
			act, err := ParseAction(entry.Action)
			if err != nil {
				return fmt.Errorf("outputschema: tool %q action: %w", name, err)
			}
			r.perToolAction[name] = act
		}
	}
	return nil
}
