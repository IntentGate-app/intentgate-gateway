package velocity

import (
	"testing"
	"time"
)

func TestRateCapTripsAtLimit(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := New(NewMemoryStore(), func() time.Time { return cur })
	lim := Limits{MaxCalls: 5, Window: time.Minute}

	for i := 0; i < 5; i++ {
		if d := l.Check("agent-1", 0, lim); !d.Allowed {
			t.Fatalf("call %d should be allowed, got %+v", i+1, d)
		}
	}
	d := l.Check("agent-1", 0, lim)
	if d.Allowed || d.Reason != ReasonRate {
		t.Fatalf("6th call should trip the rate cap, got %+v", d)
	}
	if d.Calls != 6 {
		t.Errorf("expected Calls=6 including the attempt, got %d", d.Calls)
	}
}

func TestWindowSlidesAndRecovers(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := New(NewMemoryStore(), func() time.Time { return cur })
	lim := Limits{MaxCalls: 1, Window: time.Minute}

	if d := l.Check("a", 0, lim); !d.Allowed {
		t.Fatal("first call should be allowed")
	}
	if d := l.Check("a", 0, lim); d.Allowed {
		t.Fatal("second call in window should be denied")
	}
	// Slide past the window; the earlier event falls out.
	cur = cur.Add(time.Minute + time.Second)
	if d := l.Check("a", 0, lim); !d.Allowed {
		t.Fatalf("call after window should be allowed, got %+v", d)
	}
}

func TestMonetaryCap(t *testing.T) {
	cur := time.Unix(1000, 0)
	l := New(NewMemoryStore(), func() time.Time { return cur })
	// 1000.00 cap over the window.
	lim := Limits{MaxCalls: 100, Window: time.Minute, MaxCents: 100000}

	if d := l.Check("finops", 60000, lim); !d.Allowed { // 600.00
		t.Fatalf("first 600 should be allowed, got %+v", d)
	}
	d := l.Check("finops", 60000, lim) // would total 1200.00
	if d.Allowed || d.Reason != ReasonMonetary {
		t.Fatalf("second 600 (total 1200) should trip the monetary cap, got %+v", d)
	}
	if d.Cents != 120000 {
		t.Errorf("expected Cents=120000 including the attempt, got %d", d.Cents)
	}
}

func TestDeniedAttemptsAreNotRecorded(t *testing.T) {
	cur := time.Unix(1000, 0)
	st := NewMemoryStore()
	l := New(st, func() time.Time { return cur })
	lim := Limits{MaxCalls: 1, Window: time.Minute}

	l.Check("a", 0, lim) // allowed, recorded
	l.Check("a", 0, lim) // denied
	l.Check("a", 0, lim) // denied
	if calls, _ := st.Count("a", cur, time.Minute); calls != 1 {
		t.Fatalf("denied attempts must not inflate the window, got %d", calls)
	}
}

func TestDisabledConfigAllowsEverything(t *testing.T) {
	l := New(NewMemoryStore(), nil)
	if d := l.Check("x", 9_999_999, Limits{}); !d.Allowed {
		t.Fatalf("empty limits should allow, got %+v", d)
	}
	if d := l.Check("x", 0, Limits{MaxCalls: 5}); !d.Allowed {
		t.Fatalf("zero window should disable the breaker, got %+v", d)
	}
}
