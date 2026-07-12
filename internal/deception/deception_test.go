package deception

import "testing"

func testRegistry() *StaticRegistry {
	return NewStaticRegistry([]Decoy{
		{ID: "1", Name: "admin_payments", Kind: HoneyTool, Key: "admin_payments", Pillar: "tool", OnTrip: OnTripContain},
		{ID: "2", Name: "Honey vendor record", Kind: HoneyRecord, Key: "ignored", Pillar: "data", OnTrip: OnTripHold},
		{ID: "3", Name: "Decoy token", Kind: DecoyToken, Key: "jti-decoy-123", Pillar: "identity", OnTrip: OnTripContain},
		{ID: "4", Name: "Fake admin console", Kind: DecoyZone, Key: "admin-zone", Pillar: "identity", OnTrip: OnTripContain},
		{ID: "5", Name: "Injection canary", Kind: InjectionCanary, Key: "n/a", Pillar: "counter_agentic", OnTrip: OnTripAlert},
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

func TestRecordAndCanaryKindsNotIndexedInline(t *testing.T) {
	// honey_record and injection_canary are matched elsewhere, not by an
	// inline tool/token/zone/cred probe, so they never trip here.
	d := New(testRegistry())
	if d.Check(Input{Tool: "ignored"}).Tripped {
		t.Fatal("honey_record key should not be indexed as a tool")
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
