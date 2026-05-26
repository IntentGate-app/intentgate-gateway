package outputschema

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Schema {
	t.Helper()
	s, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse(%q) failed: %v", src, err)
	}
	return s
}

func TestParse_RejectsUnknownType(t *testing.T) {
	if _, err := Parse([]byte(`{"type":"banana"}`)); err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestParse_RejectsInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte(`{not json`)); err == nil {
		t.Error("expected error for invalid json")
	}
}

func TestParseAction(t *testing.T) {
	cases := map[string]Action{
		"":        ActionStrip,
		"allow":   ActionAllow,
		"strip":   ActionStrip,
		"block":   ActionBlock,
		" ALLOW ": ActionAllow,
	}
	for in, want := range cases {
		got, err := ParseAction(in)
		if err != nil {
			t.Errorf("ParseAction(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAction(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseAction("nope"); err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestValidate_ConformingResponse(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {
			"customer_id": {"type": "string"},
			"status": {"type": "string", "enum": ["active", "inactive"]}
		},
		"required": ["customer_id"],
		"additionalProperties": false
	}`)
	in := []byte(`{"customer_id":"CUST-1","status":"active"}`)
	r := s.Validate(in)
	if r.HasViolations() {
		t.Errorf("expected clean response, got violations: %+v", r.Violations)
	}
}

func TestValidate_ExtraPropertyStripped(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {"customer_id": {"type":"string"}},
		"additionalProperties": false
	}`)
	in := []byte(`{"customer_id":"CUST-1","password_hash":"oops","email":"leak@x.com"}`)
	r := s.Validate(in)
	if r.Counts["extra_property"] != 2 {
		t.Errorf("expected 2 extra_property counts, got %d", r.Counts["extra_property"])
	}
	if strings.Contains(string(r.Stripped), "password_hash") {
		t.Errorf("stripped output still contains password_hash: %s", r.Stripped)
	}
	if strings.Contains(string(r.Stripped), "leak@x.com") {
		t.Errorf("stripped output still contains email leak: %s", r.Stripped)
	}
	if !strings.Contains(string(r.Stripped), "CUST-1") {
		t.Errorf("stripped output missing declared field: %s", r.Stripped)
	}
}

func TestValidate_AdditionalPropertiesTruePassesThrough(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {"id": {"type":"string"}},
		"additionalProperties": true
	}`)
	in := []byte(`{"id":"X","extra":42}`)
	r := s.Validate(in)
	if r.HasViolations() {
		t.Errorf("expected no violations when additionalProperties=true, got %+v", r.Violations)
	}
	if !strings.Contains(string(r.Stripped), "extra") {
		t.Errorf("expected extra to pass through, got %s", r.Stripped)
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {"id":{"type":"string"}, "status":{"type":"string"}},
		"required": ["id", "status"]
	}`)
	in := []byte(`{"id":"X"}`)
	r := s.Validate(in)
	if r.Counts["missing_required"] != 1 {
		t.Errorf("expected 1 missing_required, got %d (%+v)", r.Counts["missing_required"], r.Violations)
	}
}

func TestValidate_WrongType(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {"age":{"type":"integer"}}
	}`)
	in := []byte(`{"age":"thirty"}`)
	r := s.Validate(in)
	if r.Counts["wrong_type"] != 1 {
		t.Errorf("expected 1 wrong_type, got %d", r.Counts["wrong_type"])
	}
}

func TestValidate_EnumViolation(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {"status":{"type":"string","enum":["active","inactive"]}}
	}`)
	in := []byte(`{"status":"banana"}`)
	r := s.Validate(in)
	if r.Counts["enum_violation"] != 1 {
		t.Errorf("expected enum violation, got counts %+v", r.Counts)
	}
}

func TestValidate_ArrayItems(t *testing.T) {
	s := mustParse(t, `{
		"type": "array",
		"items": {"type":"string"}
	}`)
	in := []byte(`["a","b","c"]`)
	r := s.Validate(in)
	if r.HasViolations() {
		t.Errorf("expected clean string array, got %+v", r.Violations)
	}
	// Bad element types stripped, good ones retained.
	in = []byte(`["a", 42, "c"]`)
	r = s.Validate(in)
	if r.Counts["wrong_type"] != 1 {
		t.Errorf("expected 1 wrong_type in mixed array, got %+v", r.Counts)
	}
	if strings.Contains(string(r.Stripped), "42") {
		t.Errorf("stripped output should drop integer in string array: %s", r.Stripped)
	}
}

func TestValidate_NestedObject(t *testing.T) {
	s := mustParse(t, `{
		"type": "object",
		"properties": {
			"customer": {
				"type": "object",
				"properties": {"id":{"type":"string"}, "email":{"type":"string"}},
				"required": ["id"],
				"additionalProperties": false
			}
		},
		"required": ["customer"]
	}`)
	in := []byte(`{"customer":{"id":"X","email":"a@b.com","ssn":"redacted-me"}}`)
	r := s.Validate(in)
	if r.Counts["extra_property"] != 1 {
		t.Errorf("expected ssn flagged as extra, got %+v", r.Counts)
	}
	if strings.Contains(string(r.Stripped), "ssn") {
		t.Errorf("ssn leaked through: %s", r.Stripped)
	}
	if !strings.Contains(string(r.Stripped), "a@b.com") {
		t.Errorf("declared email field dropped: %s", r.Stripped)
	}
}

func TestValidate_MalformedJSON(t *testing.T) {
	s := mustParse(t, `{"type":"object"}`)
	r := s.Validate([]byte(`{not json`))
	if r.Counts["malformed"] != 1 {
		t.Errorf("expected malformed count, got %+v", r.Counts)
	}
}

func TestValidate_NilSchemaIsNoop(t *testing.T) {
	var s *Schema
	r := s.Validate([]byte(`{"anything":"goes"}`))
	if r.HasViolations() {
		t.Errorf("nil schema should not error: %+v", r.Violations)
	}
}

// ---------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------

func TestRegistry_LookupMissingTool(t *testing.T) {
	r := NewRegistry(ActionStrip)
	if _, _, ok := r.Lookup("ghost"); ok {
		t.Error("expected Lookup to miss for unregistered tool")
	}
}

func TestRegistry_LoadJSON(t *testing.T) {
	doc := []byte(`{
		"default_action": "strip",
		"tools": {
			"read_customer": {
				"schema": {
					"type": "object",
					"properties": {"customer_id": {"type":"string"}},
					"required": ["customer_id"],
					"additionalProperties": false
				},
				"action": "block"
			},
			"list_orders": {
				"schema": {
					"type": "object",
					"properties": {"orders": {"type":"array","items":{"type":"object"}}},
					"required": ["orders"]
				}
			}
		}
	}`)
	r := NewRegistry("")
	if err := r.LoadJSON(doc); err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}
	if names := r.ToolNames(); len(names) != 2 || names[0] != "list_orders" || names[1] != "read_customer" {
		t.Errorf("ToolNames sorted unexpectedly: %v", names)
	}
	s, act, ok := r.Lookup("read_customer")
	if !ok {
		t.Fatal("expected read_customer to be registered")
	}
	if act != ActionBlock {
		t.Errorf("expected per-tool action=block, got %v", act)
	}
	in := []byte(`{"customer_id":"X","password_hash":"secret"}`)
	res := s.Validate(in)
	if res.Counts["extra_property"] != 1 {
		t.Errorf("expected schema to flag password_hash, got %+v", res.Counts)
	}
	// Default action falls back for tools without explicit action.
	_, act2, _ := r.Lookup("list_orders")
	if act2 != ActionStrip {
		t.Errorf("expected default strip for list_orders, got %v", act2)
	}
}

func TestRegistry_LoadJSON_BadDoc(t *testing.T) {
	r := NewRegistry("")
	if err := r.LoadJSON([]byte(`not json`)); err == nil {
		t.Error("expected error on malformed registry doc")
	}
	if err := r.LoadJSON([]byte(`{"default_action":"explode"}`)); err == nil {
		t.Error("expected error on unknown action")
	}
	if err := r.LoadJSON([]byte(`{"tools":{"x":{"schema":{"type":"banana"}}}}`)); err == nil {
		t.Error("expected error on bad schema type")
	}
}

// ---------------------------------------------------------------------
// Realistic end-to-end: response leaks PII fields, registry blocks
// ---------------------------------------------------------------------

func TestRealistic_ResponseLeaksUndeclaredPII(t *testing.T) {
	r := NewRegistry(ActionStrip)
	doc := []byte(`{
		"tools": {
			"read_customer": {
				"schema": {
					"type": "object",
					"properties": {
						"customer_id": {"type": "string"},
						"name": {"type": "string"},
						"status": {"type": "string", "enum": ["active","inactive"]}
					},
					"required": ["customer_id"],
					"additionalProperties": false
				}
			}
		}
	}`)
	if err := r.LoadJSON(doc); err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	s, act, ok := r.Lookup("read_customer")
	if !ok {
		t.Fatal("read_customer not registered")
	}
	if act != ActionStrip {
		t.Fatalf("expected strip, got %v", act)
	}

	// Upstream returned everything (the bug LLM05 protects against).
	leaky := []byte(`{
		"customer_id": "CUST-1",
		"name": "Joe",
		"status": "active",
		"email": "joe@intentgate.app",
		"ssn": "123-45-6789",
		"password_hash": "$2b$12$abc"
	}`)
	res := s.Validate(leaky)
	if res.Counts["extra_property"] != 3 {
		t.Errorf("expected 3 extras stripped, got %+v", res.Counts)
	}
	// Verify the stripped output is forwardable and contains zero leaks.
	var clean map[string]any
	if err := json.Unmarshal(res.Stripped, &clean); err != nil {
		t.Fatalf("stripped output unparseable: %v", err)
	}
	for _, banned := range []string{"email", "ssn", "password_hash"} {
		if _, present := clean[banned]; present {
			t.Errorf("undeclared field %q leaked through strip: %s", banned, res.Stripped)
		}
	}
	if clean["customer_id"] != "CUST-1" {
		t.Errorf("declared field dropped: %s", res.Stripped)
	}
}
