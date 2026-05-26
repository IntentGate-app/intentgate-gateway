package faultisolation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func newTestIsolator(cfg Config, base time.Time) *Isolator {
	i := New(cfg)
	now := base
	i.now = func() time.Time { return now }
	return i
}

func TestNilIsolatorIsNoop(t *testing.T) {
	var i *Isolator
	release, err := i.Acquire(context.Background(), "any")
	if err != nil {
		t.Fatalf("nil isolator returned err: %v", err)
	}
	release(OutcomeSuccess) // must not panic
}

func TestBulkhead_LimitsConcurrent(t *testing.T) {
	i := New(Config{MaxConcurrentPerTool: 2, FailureThreshold: 100})

	r1, err := i.Acquire(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := i.Acquire(context.Background(), "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.Acquire(context.Background(), "t"); !errors.Is(err, ErrBulkheadFull) {
		t.Errorf("expected ErrBulkheadFull, got %v", err)
	}
	r1(OutcomeSuccess)
	// A permit is now free.
	r3, err := i.Acquire(context.Background(), "t")
	if err != nil {
		t.Fatalf("expected acquire to succeed after release, got %v", err)
	}
	r2(OutcomeSuccess)
	r3(OutcomeSuccess)
}

func TestBulkhead_PerToolIndependent(t *testing.T) {
	i := New(Config{MaxConcurrentPerTool: 1, FailureThreshold: 100})

	rA, err := i.Acquire(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	// Tool b should be unaffected.
	rB, err := i.Acquire(context.Background(), "b")
	if err != nil {
		t.Fatalf("tool b starved by tool a's full bulkhead: %v", err)
	}
	rA(OutcomeSuccess)
	rB(OutcomeSuccess)
}

func TestCircuit_OpensAfterThreshold(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	i := newTestIsolator(Config{FailureThreshold: 3, Cooldown: 5 * time.Second, MaxConcurrentPerTool: 100}, base)
	for n := 0; n < 3; n++ {
		release, err := i.Acquire(context.Background(), "t")
		if err != nil {
			t.Fatalf("acquire #%d unexpected err: %v", n, err)
		}
		release(OutcomeFailure)
	}
	// Threshold met → next acquire should be ErrCircuitOpen.
	if _, err := i.Acquire(context.Background(), "t"); !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen after threshold, got %v", err)
	}
}

func TestCircuit_HalfOpenAfterCooldown(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	i := newTestIsolator(Config{FailureThreshold: 2, Cooldown: time.Second, MaxConcurrentPerTool: 100}, base)
	// Trip the breaker.
	for n := 0; n < 2; n++ {
		r, _ := i.Acquire(context.Background(), "t")
		r(OutcomeFailure)
	}
	// Advance clock past cooldown.
	i.now = func() time.Time { return base.Add(2 * time.Second) }
	// First call enters half-open and is allowed through.
	r, err := i.Acquire(context.Background(), "t")
	if err != nil {
		t.Fatalf("expected probe to be allowed, got %v", err)
	}
	// A second concurrent acquire should still be blocked.
	if _, err := i.Acquire(context.Background(), "t"); !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("second acquire during half-open should be ErrCircuitOpen, got %v", err)
	}
	// Probe succeeds → breaker closes.
	r(OutcomeSuccess)
	if snap := i.Snapshot("t"); snap.State != StateClosed {
		t.Errorf("expected state=closed after successful probe, got %v", snap.State)
	}
}

func TestCircuit_HalfOpenProbeFailsReopens(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	i := newTestIsolator(Config{FailureThreshold: 1, Cooldown: time.Second, MaxConcurrentPerTool: 100}, base)
	r, _ := i.Acquire(context.Background(), "t")
	r(OutcomeFailure) // breaker opens

	i.now = func() time.Time { return base.Add(2 * time.Second) }
	r2, err := i.Acquire(context.Background(), "t")
	if err != nil {
		t.Fatalf("expected probe to be allowed, got %v", err)
	}
	r2(OutcomeFailure) // probe fails → re-open

	// Snapshot is now open at the new openedAt.
	snap := i.Snapshot("t")
	if snap.State != StateOpen {
		t.Errorf("expected state=open after failed probe, got %v", snap.State)
	}
	// Subsequent acquire fails fast.
	if _, err := i.Acquire(context.Background(), "t"); !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen after failed probe, got %v", err)
	}
}

func TestCircuit_OutcomeIgnoreDoesNotOpen(t *testing.T) {
	i := New(Config{FailureThreshold: 2, MaxConcurrentPerTool: 100})
	for n := 0; n < 10; n++ {
		r, _ := i.Acquire(context.Background(), "t")
		r(OutcomeIgnore)
	}
	if _, err := i.Acquire(context.Background(), "t"); err != nil {
		t.Errorf("OutcomeIgnore should not open breaker, got %v", err)
	}
}

func TestCircuit_SuccessResetsConsecFailures(t *testing.T) {
	i := New(Config{FailureThreshold: 3, MaxConcurrentPerTool: 100})
	// Two fails, then a success — breaker should NOT open on the next two fails.
	r, _ := i.Acquire(context.Background(), "t")
	r(OutcomeFailure)
	r, _ = i.Acquire(context.Background(), "t")
	r(OutcomeFailure)
	r, _ = i.Acquire(context.Background(), "t")
	r(OutcomeSuccess)
	r, _ = i.Acquire(context.Background(), "t")
	r(OutcomeFailure)
	r, _ = i.Acquire(context.Background(), "t")
	r(OutcomeFailure)
	if snap := i.Snapshot("t"); snap.State == StateOpen {
		t.Errorf("breaker should be closed (counter reset by success), got %v", snap.State)
	}
}

func TestSnapshotAll(t *testing.T) {
	i := New(Config{MaxConcurrentPerTool: 5})
	r, _ := i.Acquire(context.Background(), "a")
	r(OutcomeSuccess)
	r, _ = i.Acquire(context.Background(), "b")
	r(OutcomeFailure)
	snaps := i.SnapshotAll()
	if len(snaps) != 2 {
		t.Errorf("expected 2 snapshots, got %d", len(snaps))
	}
}

// ---------------------------------------------------------------------
// Concurrency stress: bulkhead never lets through more than capacity
// ---------------------------------------------------------------------

func TestBulkhead_ConcurrentStress(t *testing.T) {
	const capacity = 5
	const goroutines = 100
	i := New(Config{MaxConcurrentPerTool: capacity, FailureThreshold: 10000})

	var (
		maxInFlight int32
		curInFlight int32
		mu          sync.Mutex
	)
	var wg sync.WaitGroup
	for n := 0; n < goroutines; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := 0; it < 50; it++ {
				release, err := i.Acquire(context.Background(), "t")
				if err != nil {
					continue
				}
				mu.Lock()
				curInFlight++
				if curInFlight > maxInFlight {
					maxInFlight = curInFlight
				}
				mu.Unlock()

				time.Sleep(time.Microsecond)

				mu.Lock()
				curInFlight--
				mu.Unlock()
				release(OutcomeSuccess)
			}
		}()
	}
	wg.Wait()
	if int(maxInFlight) > capacity {
		t.Errorf("bulkhead breached: saw %d in-flight, capacity is %d", maxInFlight, capacity)
	}
}
