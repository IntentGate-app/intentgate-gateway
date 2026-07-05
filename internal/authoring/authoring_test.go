package authoring

import (
	"reflect"
	"testing"
)

func TestParse_ZoneAssignAndMembership(t *testing.T) {
	d := Parse("zone finance: agent-ledger, agent-ap\nagent-ex is in procurement")
	if d.Zones["agent-ledger"] != "finance" || d.Zones["agent-ap"] != "finance" {
		t.Fatalf("zone assign wrong: %v", d.Zones)
	}
	if d.Zones["agent-ex"] != "procurement" {
		t.Fatalf("membership wrong: %v", d.Zones)
	}
}

func TestParse_Edges(t *testing.T) {
	d := Parse("procurement may call finance\nsupport -> finance")
	want := [][2]string{{"procurement", "finance"}, {"support", "finance"}}
	if !reflect.DeepEqual(d.AllowedEdges, want) {
		t.Fatalf("edges = %v, want %v", d.AllowedEdges, want)
	}
}

func TestParse_IntraZone(t *testing.T) {
	if !Parse("allow intra-zone").AllowIntraZone {
		t.Fatal("expected intra-zone allowed")
	}
	if Parse("procurement may call finance").AllowIntraZone {
		t.Fatal("did not expect intra-zone for an edge line")
	}
}

func TestParse_Tools(t *testing.T) {
	d := Parse("finance may use read_invoice, record_ledger\nsupport tools: *")
	if got := d.ZoneTools["finance"]; !reflect.DeepEqual(got, []string{"read_invoice", "record_ledger"}) {
		t.Fatalf("finance tools = %v", got)
	}
	if got := d.ZoneTools["support"]; !reflect.DeepEqual(got, []string{"*"}) {
		t.Fatalf("support tools = %v", got)
	}
}

func TestParse_Tenants(t *testing.T) {
	d := Parse("finance in tenant acme\nsupport tenants: acme, beta")
	if got := d.ZoneTenants["finance"]; !reflect.DeepEqual(got, []string{"acme"}) {
		t.Fatalf("finance tenants = %v", got)
	}
	if got := d.ZoneTenants["support"]; !reflect.DeepEqual(got, []string{"acme", "beta"}) {
		t.Fatalf("support tenants = %v", got)
	}
}

func TestParse_CommentsBlankAndWarnings(t *testing.T) {
	d := Parse("# a comment\n\nfinance may use read_invoice\nthis is gibberish")
	if len(d.ZoneTools["finance"]) != 1 {
		t.Fatalf("expected finance tool parsed, got %v", d.ZoneTools)
	}
	if len(d.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %v", d.Warnings)
	}
}

func TestParse_Deterministic(t *testing.T) {
	text := "support -> finance\nprocurement -> finance"
	a := Parse(text)
	b := Parse(text)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("parse not deterministic")
	}
	if a.AllowedEdges[0][0] != "procurement" {
		t.Fatalf("edges not sorted: %v", a.AllowedEdges)
	}
}
