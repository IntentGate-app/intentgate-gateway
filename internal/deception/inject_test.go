package deception

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecoyToolDefsOnlyHoneyTools(t *testing.T) {
	decoys := []Decoy{
		{Kind: HoneyTool, Key: "admin_payments", Synthetic: "Process a privileged payment."},
		{Kind: HoneyTool, Name: "bulk_export_users"}, // no Key -> uses Name, default desc
		{Kind: HoneyRecord, Key: "fake_record"},      // not a tool -> skipped
		{Kind: HoneyTool},                            // no name at all -> skipped
	}
	defs := DecoyToolDefs(decoys)
	if len(defs) != 2 {
		t.Fatalf("expected 2 decoy tools, got %d", len(defs))
	}
	var first map[string]any
	if err := json.Unmarshal(defs[0], &first); err != nil {
		t.Fatal(err)
	}
	if first["name"] != "admin_payments" || first["description"] != "Process a privileged payment." {
		t.Errorf("unexpected first decoy: %v", first)
	}
	var second map[string]any
	_ = json.Unmarshal(defs[1], &second)
	if second["name"] != "bulk_export_users" || second["description"] == "" {
		t.Errorf("second decoy should use Name and a default description: %v", second)
	}
}

func TestAppendDecoyToolsMergesAndPreserves(t *testing.T) {
	result := json.RawMessage(`{"tools":[{"name":"get_invoice"}],"nextCursor":"x"}`)
	decoys := []Decoy{{Kind: HoneyTool, Key: "admin_payments"}}
	out, n, err := AppendDecoyTools(result, decoys)
	if err != nil || n != 1 {
		t.Fatalf("append failed: n=%d err=%v", n, err)
	}
	var obj struct {
		Tools []map[string]any `json:"tools"`
		Next  string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if len(obj.Tools) != 2 || obj.Tools[0]["name"] != "get_invoice" || obj.Tools[1]["name"] != "admin_payments" {
		t.Errorf("real tool must come first, decoy appended: %v", obj.Tools)
	}
	if obj.Next != "x" {
		t.Errorf("other result fields must be preserved")
	}
}

func TestAppendDecoyToolsNoDecoysIsNoOp(t *testing.T) {
	result := json.RawMessage(`{"tools":[{"name":"a"}]}`)
	out, n, err := AppendDecoyTools(result, []Decoy{{Kind: HoneyRecord, Key: "r"}})
	if err != nil || n != 0 || string(out) != string(result) {
		t.Errorf("no honey tools should be a no-op, got n=%d out=%s", n, out)
	}
}

func TestCanaryValues(t *testing.T) {
	decoys := []Decoy{
		{Kind: InjectionCanary, Synthetic: "IG-CANARY-9x"},
		{Kind: HoneyCredential, Key: "AKIAFAKEFAKEFAKE0000"},
		{Kind: HoneyRecord, Synthetic: "customer 00000 / SSN 000-00-0000"},
		{Kind: HoneyTool, Key: "not_a_canary"},
	}
	v := CanaryValues(decoys)
	if len(v) != 3 {
		t.Fatalf("expected 3 canary values, got %d: %v", len(v), v)
	}
}

func TestInjectCanaryJSONObject(t *testing.T) {
	body := []byte(`{"customer":"acme","status":"active"}`)
	out, ok := InjectCanary(body, []string{"AKIAFAKE0000"})
	if !ok {
		t.Fatal("expected canary seeded")
	}
	if !strings.Contains(string(out), "AKIAFAKE0000") {
		t.Errorf("canary value should be present: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("output must stay valid JSON: %v", err)
	}
	if m["customer"] != "acme" {
		t.Error("original fields must survive")
	}
}

func TestInjectCanaryTextAndEmpty(t *testing.T) {
	out, ok := InjectCanary([]byte("plain results here"), []string{"CANARY-1"})
	if !ok || !strings.Contains(string(out), "CANARY-1") {
		t.Errorf("text body should get the marker appended: %s", out)
	}
	if _, ok := InjectCanary([]byte("x"), nil); ok {
		t.Error("no canaries should be a no-op")
	}
}
