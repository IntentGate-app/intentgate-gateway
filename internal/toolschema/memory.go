package toolschema

import "sync"

// MemoryStore is an in-memory baseline store for tests and single-node
// deployments. Production uses the Postgres-backed store.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[string]Baseline
}

// NewMemoryStore returns an empty in-memory baseline store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{m: make(map[string]Baseline)}
}

func baselineKey(tenant, tool string) string { return tenant + "\x00" + tool }

// Get returns the approved baseline for (tenant, tool), if any.
func (s *MemoryStore) Get(tenant, tool string) (Baseline, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.m[baselineKey(tenant, tool)]
	return b, ok
}

// Put records or replaces an approved baseline.
func (s *MemoryStore) Put(b Baseline) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[baselineKey(b.Tenant, b.Tool)] = b
	return nil
}
