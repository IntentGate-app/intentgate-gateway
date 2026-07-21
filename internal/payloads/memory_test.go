package payloads

import (
	"context"
	"testing"
	"time"
)

func rec(id string, expires time.Time) Record {
	return Record{
		EventID:    id,
		Tenant:     "acme",
		AgentID:    "agent-procure-1",
		Tool:       "agent:agent-finance-1",
		RawSHA256:  HashRaw([]byte("hello")),
		RawBytes:   5,
		Body:       []byte("hello"),
		CapturedAt: time.Now(),
		ExpiresAt:  expires,
	}
}

func TestPutGetRoundTrip(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	if err := s.Put(ctx, rec("e1", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "acme", "e1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != "hello" {
		t.Fatalf("body = %q", got.Body)
	}
	if got.RawSHA256 != HashRaw([]byte("hello")) {
		t.Fatal("hash not round-tripped")
	}
}

// A payload belongs to one tenant. Reading it from another must miss, or the
// store becomes a cross-tenant data leak reachable by guessing an event id.
func TestGetIsTenantScoped(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.Put(ctx, rec("e1", time.Now().Add(time.Hour)))
	if _, err := s.Get(ctx, "other", "e1"); err != ErrNotFound {
		t.Fatalf("cross-tenant read returned %v, want ErrNotFound", err)
	}
}

// Retention has to hold on read. If an expired row is readable until a sweeper
// runs, the retention promise is only as good as a background task.
func TestExpiredRowIsNotReadableBeforePurge(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.Put(ctx, rec("e1", time.Now().Add(-time.Second)))
	if _, err := s.Get(ctx, "acme", "e1"); err != ErrNotFound {
		t.Fatalf("expired read returned %v, want ErrNotFound", err)
	}
}

// A retried capture must not be able to swap the body out from under the hash
// already written to the audit event.
func TestPutIsFirstWriteWins(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.Put(ctx, rec("e1", time.Now().Add(time.Hour)))

	second := rec("e1", time.Now().Add(time.Hour))
	second.Body = []byte("tampered")
	second.RawSHA256 = HashRaw([]byte("tampered"))
	if err := s.Put(ctx, second); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Get(ctx, "acme", "e1")
	if string(got.Body) != "hello" {
		t.Fatalf("second Put overwrote the body: %q", got.Body)
	}
}

func TestPurgeRemovesOnlyExpired(t *testing.T) {
	s := NewMemory()
	ctx := context.Background()
	_ = s.Put(ctx, rec("live", time.Now().Add(time.Hour)))
	_ = s.Put(ctx, rec("dead", time.Now().Add(-time.Hour)))

	n, err := s.Purge(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d, want 1", n)
	}
	if _, err := s.Get(ctx, "acme", "live"); err != nil {
		t.Fatalf("purge removed a live row: %v", err)
	}
}

func TestGetMissingIsNotFound(t *testing.T) {
	if _, err := NewMemory().Get(context.Background(), "acme", "nope"); err != ErrNotFound {
		t.Fatalf("got %v, want ErrNotFound", err)
	}
}
