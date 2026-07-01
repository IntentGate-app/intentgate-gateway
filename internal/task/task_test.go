package task

import (
	"context"
	"testing"
)

// testCfg returns deterministic small thresholds so the drift arithmetic
// in the tests is easy to follow.
func testCfg() Config {
	c := DefaultConfig()
	c.Enabled = true
	c.OffPlanWeight = 3
	c.OverBudgetWeight = 2
	c.DistinctWeight = 2
	c.PlanSlack = 1
	c.MaxCalls = 5
	c.WarnScore = 3
	c.BlockScore = 6
	return c
}

func TestBindDisabledIsNoop(t *testing.T) {
	ctx := context.Background()
	b := NewBinder(NewMemoryStore(), Config{Enabled: false})
	res, err := b.Bind(ctx, "acme", "a1", "t1", "tool", []string{"tool"}, "sum")
	if err != nil || res.Outcome != OutcomeAllow {
		t.Fatalf("disabled binder must be a no-op allow: outcome=%v err=%v", res.Outcome, err)
	}
}

func TestBindEmptyTaskIDIsNoop(t *testing.T) {
	ctx := context.Background()
	b := NewBinder(NewMemoryStore(), testCfg())
	res, _ := b.Bind(ctx, "acme", "a1", "", "tool", []string{"tool"}, "sum")
	if res.Outcome != OutcomeAllow {
		t.Fatalf("empty task id must be a no-op allow, got %v", res.Outcome)
	}
}

func TestBindOnPlanStaysActive(t *testing.T) {
	ctx := context.Background()
	b := NewBinder(NewMemoryStore(), testCfg())
	plan := []string{"read_tickets", "read_customer"}
	for i := 0; i < 4; i++ {
		res, err := b.Bind(ctx, "acme", "a1", "t1", "read_tickets", plan, "summarize tickets")
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != OutcomeAllow || res.Drift != 0 {
			t.Fatalf("on-plan call %d: outcome=%v drift=%d; want allow, 0", i, res.Outcome, res.Drift)
		}
	}
}

func TestBindOffPlanFlagsThenBlocks(t *testing.T) {
	ctx := context.Background()
	b := NewBinder(NewMemoryStore(), testCfg())
	plan := []string{"read_tickets"}

	// Call 1 establishes the plan (on-plan): drift 0.
	if res, _ := b.Bind(ctx, "acme", "a1", "t1", "read_tickets", plan, "sum"); res.Outcome != OutcomeAllow {
		t.Fatalf("call 1 should allow, got %v", res.Outcome)
	}
	// Call 2 off-plan: +3 → drift 3 == warn → flag.
	res, _ := b.Bind(ctx, "acme", "a1", "t1", "export_all", plan, "sum")
	if res.Outcome != OutcomeFlag {
		t.Fatalf("call 2 off-plan should flag (drift=%d), got %v", res.Drift, res.Outcome)
	}
	// Call 3 off-plan: +3 off-plan +2 distinct → drift 8 >= block → block.
	res, _ = b.Bind(ctx, "acme", "a1", "t1", "send_email", plan, "sum")
	if res.Outcome != OutcomeBlock {
		t.Fatalf("call 3 off-plan should block (drift=%d), got %v", res.Drift, res.Outcome)
	}
}

func TestBindPlanCannotWidenMidTask(t *testing.T) {
	ctx := context.Background()
	b := NewBinder(NewMemoryStore(), testCfg())
	// Establish a narrow plan.
	b.Bind(ctx, "acme", "a1", "t1", "read_tickets", []string{"read_tickets"}, "sum")
	// A later call tries to widen the plan AND use the new tool. The stored
	// envelope wins, so export_all is still off-plan.
	res, _ := b.Bind(ctx, "acme", "a1", "t1", "export_all",
		[]string{"read_tickets", "export_all"}, "sum")
	if res.Outcome == OutcomeAllow {
		t.Fatalf("widening the plan mid-task must not let an off-plan tool through; drift=%d", res.Drift)
	}
}

func TestBindHaltedStaysHalted(t *testing.T) {
	ctx := context.Background()
	cfg := testCfg()
	cfg.BlockScore = 3 // block on the first off-plan call
	b := NewBinder(NewMemoryStore(), cfg)

	b.Bind(ctx, "acme", "a1", "t1", "read", []string{"read"}, "sum") // establish
	if res, _ := b.Bind(ctx, "acme", "a1", "t1", "off", []string{"read"}, "sum"); res.Outcome != OutcomeBlock {
		t.Fatalf("off-plan should block, got %v (drift %d)", res.Outcome, res.Drift)
	}
	// A subsequent on-plan call must still be blocked: a halted task stays
	// halted until an operator clears it.
	if res, _ := b.Bind(ctx, "acme", "a1", "t1", "read", []string{"read"}, "sum"); res.Outcome != OutcomeBlock {
		t.Fatalf("halted task must stay halted for an on-plan call, got %v", res.Outcome)
	}
}

func TestBindOverBudget(t *testing.T) {
	ctx := context.Background()
	cfg := testCfg()
	cfg.MaxCalls = 2
	cfg.OverBudgetWeight = 2
	cfg.WarnScore = 2
	cfg.BlockScore = 100 // isolate the over-budget signal from block
	b := NewBinder(NewMemoryStore(), cfg)
	plan := []string{"read"}
	// 3 on-plan calls; the 3rd is past MaxCalls=2 → over-budget drift.
	b.Bind(ctx, "acme", "a1", "t1", "read", plan, "s")
	b.Bind(ctx, "acme", "a1", "t1", "read", plan, "s")
	res, _ := b.Bind(ctx, "acme", "a1", "t1", "read", plan, "s")
	if res.Drift < 2 {
		t.Fatalf("over-budget call should add drift, got %d", res.Drift)
	}
	if res.Outcome != OutcomeFlag {
		t.Fatalf("over-budget should flag at warn, got %v", res.Outcome)
	}
}

func TestTaskMemoryStoreIsolationAndTenancy(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	if got, err := s.Get(ctx, "acme", "nope"); err != nil || got != nil {
		t.Fatalf("missing get should be nil,nil: %v %v", got, err)
	}

	if err := s.Upsert(ctx, &Task{ID: "t1", Tenant: "acme", Agent: "a1", Status: StatusActive, Calls: 1}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "acme", "t1")
	if err != nil || got == nil || got.Calls != 1 {
		t.Fatalf("get t1: %+v %v", got, err)
	}
	// Mutating the returned copy must not affect stored state.
	got.Calls = 99
	if again, _ := s.Get(ctx, "acme", "t1"); again.Calls != 1 {
		t.Fatalf("store must be isolated from returned copy, got %d", again.Calls)
	}
	// Cross-tenant get is nil.
	if other, _ := s.Get(ctx, "other", "t1"); other != nil {
		t.Fatalf("cross-tenant get must be nil")
	}

	// List filters by tenant; "" is the superadmin all-view.
	_ = s.Upsert(ctx, &Task{ID: "t2", Tenant: "other", Status: StatusActive})
	if acme, _ := s.List(ctx, "acme", 100, 0); len(acme) != 1 {
		t.Fatalf("acme list want 1, got %d", len(acme))
	}
	if all, _ := s.List(ctx, "", 100, 0); len(all) != 2 {
		t.Fatalf("all list want 2, got %d", len(all))
	}
}
