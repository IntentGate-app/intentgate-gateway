package payloads

import (
	"context"
	"sync"
	"time"
)

// MemoryStore keeps captured responses in process. Used in tests and in
// single-node deployments with no Postgres.
//
// It is not a production store for a multi-replica gateway: each replica would
// hold a different subset, so a payload captured on one node would read as
// missing on another. That failure is silent and looks like expiry, which is
// why NewMemory is not the default anywhere.
type MemoryStore struct {
	mu   sync.RWMutex
	rows map[string]Record
}

func NewMemory() *MemoryStore {
	return &MemoryStore{rows: make(map[string]Record)}
}

func key(tenant, eventID string) string { return tenant + "\x00" + eventID }

func (m *MemoryStore) Put(_ context.Context, rec Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key(rec.Tenant, rec.EventID)
	// First write wins. A retry must not be able to replace the body that was
	// hashed into the audit event.
	if _, ok := m.rows[k]; ok {
		return nil
	}
	m.rows[k] = rec
	return nil
}

func (m *MemoryStore) Get(_ context.Context, tenant, eventID string) (Record, error) {
	m.mu.RLock()
	rec, ok := m.rows[key(tenant, eventID)]
	m.mu.RUnlock()
	if !ok {
		return Record{}, ErrNotFound
	}
	// Expiry is enforced on read, not only by Purge. A store that returns
	// expired rows until a sweeper happens to run is not honouring retention.
	if !rec.ExpiresAt.IsZero() && !time.Now().Before(rec.ExpiresAt) {
		return Record{}, ErrNotFound
	}
	return rec, nil
}

func (m *MemoryStore) Purge(_ context.Context, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, rec := range m.rows {
		if !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt) {
			delete(m.rows, k)
			n++
		}
	}
	return n, nil
}
