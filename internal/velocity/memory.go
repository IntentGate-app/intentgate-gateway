package velocity

import (
	"sync"
	"time"
)

type event struct {
	ts    time.Time
	cents int64
}

// MemoryStore is an in-process trailing-event store for single-node
// deployments and tests. Events are pruned lazily on each Count.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string][]event
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: make(map[string][]event)}
}

// Count prunes events older than the window and returns the surviving count
// and summed cents.
func (s *MemoryStore) Count(key string, now time.Time, window time.Duration) (int, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-window)
	evs := s.m[key]
	kept := evs[:0]
	var cents int64
	for _, e := range evs {
		if e.ts.After(cutoff) {
			kept = append(kept, e)
			cents += e.cents
		}
	}
	if len(kept) == 0 {
		delete(s.m, key)
	} else {
		s.m[key] = kept
	}
	return len(kept), cents
}

// Add appends one event under key.
func (s *MemoryStore) Add(key string, now time.Time, cents int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = append(s.m[key], event{ts: now, cents: cents})
}
