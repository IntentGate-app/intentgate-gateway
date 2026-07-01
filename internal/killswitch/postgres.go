package killswitch

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is the migration applied at startup. Idempotent via
// IF NOT EXISTS, matching the revocation store.
//
//go:embed schema.sql
var schemaSQL string

// PostgresStore is a durable, multi-replica-safe kill-switch store.
// An engaged breaker in the shared table is honoured by every gateway
// replica on its next request.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects, pings to fail-fast, runs the embedded
// migration, and returns a ready store. The caller owns the store and
// must Close it on shutdown.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("killswitch: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("killswitch: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("killswitch: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("killswitch: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("killswitch: migrate: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases the connection pool. Safe to call multiple times.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

// Active returns true if a global kill exists, a kill on the caller's
// tenant exists, or a kill on this agent within this tenant exists.
// One indexed lookup covering all three scopes; the most specific
// matching row (agent, then tenant, then global) is returned for audit.
func (s *PostgresStore) Active(ctx context.Context, tenant, agentID string) (bool, Entry, error) {
	const q = `
		SELECT scope, tenant, value, reason, set_at, set_by
		FROM kill_switch
		WHERE scope = 'global'
		   OR (scope = 'tenant' AND tenant = $1)
		   OR (scope = 'agent'  AND tenant = $1 AND value = $2)
		ORDER BY CASE scope WHEN 'agent' THEN 0 WHEN 'tenant' THEN 1 ELSE 2 END
		LIMIT 1
	`
	var e Entry
	var scope string
	err := s.pool.QueryRow(ctx, q, tenant, agentID).Scan(
		&scope, &e.Tenant, &e.Value, &e.Reason, &e.SetAt, &e.SetBy)
	if err != nil {
		// pgx returns ErrNoRows when nothing matched; that is the common
		// "not halted" path, not an error.
		if errors.Is(err, pgx.ErrNoRows) {
			return false, Entry{}, nil
		}
		return false, Entry{}, fmt.Errorf("killswitch: query: %w", err)
	}
	e.Type = ScopeType(scope)
	return true, e, nil
}

// Engage inserts a kill. Idempotent per (scope, tenant, value): a
// repeat updates the reason but keeps the original set_at.
func (s *PostgresStore) Engage(ctx context.Context, e Entry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	const q = `
		INSERT INTO kill_switch (scope, tenant, value, reason, set_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scope, tenant, value) DO UPDATE SET reason = EXCLUDED.reason
	`
	if _, err := s.pool.Exec(ctx, q, string(e.Type), e.Tenant, e.Value, e.Reason, e.SetBy); err != nil {
		return fmt.Errorf("killswitch: insert: %w", err)
	}
	return nil
}

// Release deletes the kill identified by (scope, tenant, value). Not an
// error if no row matched.
func (s *PostgresStore) Release(ctx context.Context, t ScopeType, tenant, value string) error {
	const q = `DELETE FROM kill_switch WHERE scope = $1 AND tenant = $2 AND value = $3`
	if _, err := s.pool.Exec(ctx, q, string(t), tenant, value); err != nil {
		return fmt.Errorf("killswitch: delete: %w", err)
	}
	return nil
}

// List returns all engaged kills, most-recent first.
func (s *PostgresStore) List(ctx context.Context) ([]Entry, error) {
	const q = `
		SELECT scope, tenant, value, reason, set_at, set_by
		FROM kill_switch
		ORDER BY set_at DESC
	`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("killswitch: query list: %w", err)
	}
	defer rows.Close()
	out := make([]Entry, 0, 8)
	for rows.Next() {
		var e Entry
		var scope string
		if err := rows.Scan(&scope, &e.Tenant, &e.Value, &e.Reason, &e.SetAt, &e.SetBy); err != nil {
			return nil, fmt.Errorf("killswitch: scan: %w", err)
		}
		e.Type = ScopeType(scope)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("killswitch: rows iter: %w", err)
	}
	return out, nil
}
