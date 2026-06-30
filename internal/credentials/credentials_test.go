package credentials

import (
	"reflect"
	"testing"
)

func TestNew_ParsesAndSelectsPerTool(t *testing.T) {
	s, err := New(map[string]string{
		"transfer_funds": "Authorization: Bearer pay-secret",
		"read_invoice":   "X-Api-Key: inv-secret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := s.HeaderFor("transfer_funds"); !reflect.DeepEqual(got, map[string]string{"Authorization": "Bearer pay-secret"}) {
		t.Errorf("transfer_funds header = %v", got)
	}
	if got := s.HeaderFor("read_invoice"); !reflect.DeepEqual(got, map[string]string{"X-Api-Key": "inv-secret"}) {
		t.Errorf("read_invoice header = %v", got)
	}
	// A tool with no per-tool entry returns nil so the caller falls back
	// to the global upstream credential.
	if got := s.HeaderFor("unmapped_tool"); got != nil {
		t.Errorf("unmapped tool should be nil, got %v", got)
	}
}

func TestNew_RejectsBadHeader(t *testing.T) {
	if _, err := New(map[string]string{"t": "no-colon-here"}); err == nil {
		t.Fatal("expected error for malformed header")
	}
}

func TestSetRotatesAndRemoveFallsBack(t *testing.T) {
	s, _ := New(nil)

	if err := s.Set("send_email", "Authorization: Bearer v1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := s.HeaderFor("send_email")["Authorization"]; got != "Bearer v1" {
		t.Errorf("after Set, want Bearer v1, got %q", got)
	}

	// Rotation: a new value for the same tool replaces the old one live.
	if err := s.Set("send_email", "Authorization: Bearer v2"); err != nil {
		t.Fatalf("Set rotate: %v", err)
	}
	if got := s.HeaderFor("send_email")["Authorization"]; got != "Bearer v2" {
		t.Errorf("after rotate, want Bearer v2, got %q", got)
	}

	s.Remove("send_email")
	if got := s.HeaderFor("send_email"); got != nil {
		t.Errorf("after Remove, want nil (fall back to global), got %v", got)
	}
}

func TestNilStoreIsSafe(t *testing.T) {
	var s *Store
	if got := s.HeaderFor("anything"); got != nil {
		t.Errorf("nil store HeaderFor should be nil, got %v", got)
	}
	if got := s.Tools(); got != nil {
		t.Errorf("nil store Tools should be nil, got %v", got)
	}
}
