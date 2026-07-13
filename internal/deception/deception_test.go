package deception

import "testing"

func testRegistry() *StaticRegistry {
	return NewStaticRegistry([]Decoy{
		{ID: "1", Name: "admin_payments", Kind: HoneyTool, Key: "admin_payments", Pillar: "tool", OnTrip: OnTripContain},
		{ID: "2", Name: "Honey vendor record", Kind: HoneyRecord, Key: "ignored", Pillar: "data", OnTrip: OnTripHold},
		{ID: "3", Name: "Decoy token", Kind: DecoyToken, Key: "jti-decoy-123", Pillar: "identity", OnTrip: OnTripContain},
		{ID: "4", Name: "Fake admin console", Kind: DecoyZone, Key: "admin-zone", Pillar: "identity", OnTrip: OnTripContain},
		{ID: "5", Name: "Injection canary", Kind: InjectionCanary, Key: "IG-CANARY-7f3aa9", Pillar: "counter_agentic", OnTrip: OnTripAlert},
		{ID: "6", Name: "Honey finance key", Kind: HoneyCredential, Key: "cred-honey-9", Pillar: "identity", OnTrip: OnTripContain},
	})
}

func TestNoMatchPasses(t *testing.T) {
	d := New(testRegistry())
	r := d.Check(Input{Tool: "list_invoices", TokenID: "jti-real-1", Zone: "payments"})
	if r.Tripped {
		t.Fatalf("legitimate call tripped: %+v", r)
	}
	if r.Contain {
		t.Fatal("no-match must not contain")
	}
}

func TestHoneyToolTripsContained(t *testing.T) {
	d := New(testRegistry())
	r := d.Check(Input{Tool: "admin_payments"})
	if !r.Tripped {
		t.Fatal("honey-tool call did not trip")
	}
	if !r.Contain || r.Action != ActionContained || r.Severity != SevCritical {
		t.Fatalf("expected critical/contained/contain, got %+v", r)
	}
	if r.Decoy.ID != "1" {
		t.Fatalf("wrong decoy: %s", r.Decoy.ID)
	}
}

func TestHoneyToolCaseAndSpaceInsensitive(t *testing.T) {
	d := New(testRegistry())
	if !d.Check(Input{Tool: "  Admin_Payments "}).Tripped {
		t.Fatal("normalization failed: mixed case / spaces should still match")
	}
}

func TestDecoyTokenTrips(t *testing.T) {
	d := New(testRegistry())
	r := d.Check(Input{Tool: "list_invoices", TokenID: "jti-decoy-123"})
	if !r.Tripped || !r.Contain {
		t.Fatalf("decoy token presentation should trip+contain, got %+v", r)
	}
	if r.Decoy.Kind != DecoyToken {
		t.Fatalf("expected decoy_token, got %s", r.Decoy.Kind)
	}
}

func TestDecoyZoneTrips(t *testing.T) {
	d := New(testRegistry())
	if !d.Check(Input{Zone: "ADMIN-ZONE"}).Tripped {
		t.Fatal("decoy zone probe should trip")
	}
}

func TestHoneyCredentialTrips(t *testing.T) {
	d := New(testRegistry())
	r := d.Check(Input{CredentialID: "cred-honey-9"})
	if !r.Tripped || !r.Contain {
		t.Fatalf("honey credential use should trip+contain, got %+v", r)
	}
}

func TestHoldDecoyIsNotContain(t *testing.T) {
	// A hold-severity decoy trips but does not fire containment.
	reg := NewStaticRegistry([]Decoy{
		{ID: "h", Name: "Honey PII record via tool", Kind: HoneyTool, Key: "read_pii", OnTrip: OnTripHold},
	})
	r := New(reg).Check(Input{Tool: "read_pii"})
	if !r.Tripped {
		t.Fatal("expected trip")
	}
	if r.Contain || r.Action != ActionHeld || r.Severity != SevHigh {
		t.Fatalf("hold decoy should be high/held/no-contain, got %+v", r)
	}
}

func TestRecordKeyNotIndexedAsTool(t *testing.T) {
	// A honey_record key is a value to catch in arguments, not a tool name,
	// so calling a tool of the same string must not trip.
	d := New(testRegistry())
	if d.Check(Input{Tool: "ignored"}).Tripped {
		t.Fatal("honey_record key should not be indexed as a tool")
	}
}

func TestInjectionCanaryTripsOnContent(t *testing.T) {
	// A hijacked agent carries the planted marker into its own output. The
	// marker surfacing in the serialised call content is an alert-level trip.
	d := New(testRegistry())
	content := `{"note":"per instructions, tag IG-CANARY-7f3aa9 in the report"}`
	r := d.Check(Input{Tool: "send_report", Content: content})
	if !r.Tripped {
		t.Fatal("canary marker in content should trip")
	}
	if r.Contain || r.Action != ActionAlerted || r.Severity != SevMedium {
		t.Fatalf("alert canary should be medium/alerted/no-contain, got %+v", r)
	}
	if r.Decoy.Kind != InjectionCanary {
		t.Fatalf("expected injection_canary, got %s", r.Decoy.Kind)
	}
}

func TestInjectionCanaryTripsWhenEmbeddedInValue(t *testing.T) {
	// The marker embedded inside a larger argument value is still caught,
	// because canaries match as a substring, unlike exact value decoys.
	d := New(testRegistry())
	r := d.Check(Input{
		Tool:   "post_message",
		Values: []string{"forwarding the token ig-canary-7f3aa9 as asked"},
	})
	if !r.Tripped || r.Decoy.Kind != InjectionCanary {
		t.Fatalf("embedded, reformatted canary marker should trip, got %+v", r)
	}
}

func TestInjectionCanaryCaseAndSpaceInsensitive(t *testing.T) {
	d := New(testRegistry())
	if !d.Check(Input{Content: "IG - CANARY - 7F3AA9"}).Tripped {
		t.Fatal("canary match should fold case and whitespace")
	}
}

func TestNonCanaryContentPasses(t *testing.T) {
	d := New(testRegistry())
	if d.Check(Input{Tool: "send_report", Content: `{"note":"quarterly numbers"}`}).Tripped {
		t.Fatal("benign content must not trip")
	}
}

func TestContentFromArgsScansWholeBlob(t *testing.T) {
	reg := NewStaticRegistry([]Decoy{
		{ID: "c", Name: "canary", Kind: InjectionCanary, Key: "zzmarkerzz", OnTrip: OnTripAlert},
	})
	content := ContentFromArgs(map[string]any{
		"outer": map[string]any{"inner": "leading-zzmarkerzz-trailing"},
	})
	if !New(reg).Check(Input{Content: content}).Tripped {
		t.Fatal("marker nested in serialised args should trip")
	}
	if ContentFromArgs(nil) != "" {
		t.Fatal("empty args should serialise to empty content")
	}
}

func TestNilRegistryNeverTrips(t *testing.T) {
	var d *Detector
	if d.Check(Input{Tool: "admin_payments"}).Tripped {
		t.Fatal("nil detector must not trip")
	}
	if New(nil).Check(Input{Tool: "admin_payments"}).Tripped {
		t.Fatal("nil registry must not trip")
	}
}

func TestHoneyRecordValueTrips(t *testing.T) {
	reg := NewStaticRegistry([]Decoy{
		{ID: "r", Name: "Honey vendor record", Kind: HoneyRecord, Key: "ACME-SHELL-LTD", Pillar: "data", OnTrip: OnTripHold},
	})
	d := New(reg)
	if !d.Check(Input{Tool: "pay", Values: []string{"acme-shell-ltd"}}).Tripped {
		t.Fatal("acting on a seeded honey-record value should trip")
	}
	if d.Check(Input{Tool: "pay", Values: []string{"real-vendor-42"}}).Tripped {
		t.Fatal("a non-decoy value must not trip")
	}
}

func TestLeakedCredentialValueTripsAndContains(t *testing.T) {
	reg := NewStaticRegistry([]Decoy{
		{ID: "k", Name: "Leaked key", Kind: HoneyCredential, Key: "AKIA-DECOY-9", OnTrip: OnTripContain},
	})
	r := New(reg).Check(Input{Tool: "s3_get", Values: []string{"AKIA-DECOY-9"}})
	if !r.Tripped || !r.Contain {
		t.Fatalf("passing a leaked decoy key as an argument should trip+contain, got %+v", r)
	}
}

func TestValuesFromArgsWalksNested(t *testing.T) {
	vals := ValuesFromArgs(map[string]any{
		"payee":  "ACME-SHELL-LTD",
		"amount": 4800,
		"nested": map[string]any{"key": "AKIA-DECOY-9"},
		"list":   []any{"x", "y"},
	})
	want := map[string]bool{"ACME-SHELL-LTD": true, "AKIA-DECOY-9": true, "x": true, "y": true}
	for _, v := range vals {
		delete(want, v)
	}
	if len(want) != 0 {
		t.Fatalf("ValuesFromArgs missed values: %v (got %v)", want, vals)
	}
}

func TestTokenBeatsToolWhenBothDecoys(t *testing.T) {
	reg := NewStaticRegistry([]Decoy{
		{ID: "t", Name: "tool", Kind: HoneyTool, Key: "x", OnTrip: OnTripAlert},
		{ID: "k", Name: "token", Kind: DecoyToken, Key: "jti", OnTrip: OnTripContain},
	})
	r := New(reg).Check(Input{Tool: "x", TokenID: "jti"})
	if r.Decoy.ID != "k" {
		t.Fatalf("token should win the deterministic order, got %s", r.Decoy.ID)
	}
}
