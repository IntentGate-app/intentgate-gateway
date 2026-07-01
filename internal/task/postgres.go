package task

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// PostgresStore is a durable, multi-replica-safe task store. Task drift
// state is shared across replicas so a task's trajectory is consistent
// however its calls are load-balanced.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore connects, pings, runs the embedded migration, and
// returns a ready store. The caller owns it and must Close on shutdown.
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("task: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("task: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("task: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("task: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("task: migrate: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// Close releases the pool. Safe to call multiple times.
func (s *PostgresStore) Close() {
	if s.pool != nil {
		s.pool.Close()
	}
}

func scanTask(row pgx.Row) (*Task, error) {
	var t Task
	err := row.Scan(&t.ID, &t.Tenant, &t.Agent, &t.Intent, &t.Plan, &t.Tools,
		&t.Calls, &t.Drift, &t.Status, &t.StartedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Get returns the task or (nil, nil) if none exists.
func (s *PostgresStore) Get(ctx context.Context, tenant, id string) (*Task, error) {
	const q = `
		SELECT id, tenant, agent, intent, plan, tools, calls, drift, status, started_at, updated_at
		FROM tasks WHERE tenant = $1 AND id = $2
	`
	t, err := scanTask(s.pool.QueryRow(ctx, q, tenant, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("task: get: %w", err)
	}
	return t, nil
}

// Upsert inserts or updates the task by (tenant, id).
func (s *PostgresStore) Upsert(ctx context.Context, t *Task) error {
	const q = `
		INSERT INTO tasks (id, tenant, agent, intent, plan, tools, calls, drift, status, started_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant, id) DO UPDATE SET
			agent = EXCLUDED.agent,
			tools = EXCLUDED.tools,
			calls = EXCLUDED.calls,
			drift = EXCLUDED.drift,
			status = EXCLUDED.status,
			updated_at = EXCLUDED.updated_at
	`
	started := t.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	updated := t.UpdatedAt
	if updated.IsZero() {
		updated = time.Now().UTC()
	}
	if _, err := s.pool.Exec(ctx, q,
		t.ID, t.Tenant, t.Agent, t.Intent, t.Plan, t.Tools,
		t.Calls, t.Drift, string(t.Status), started, updated); err != nil {
		return fmt.Errorf("task: upsert: %w", err)
	}
	return nil
}

// List returns recent tasks, most-recently-updated first.
func (s *PostgresStore) List(ctx context.Context, tenant string, limit, offset int) ([]*Task, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if tenant == "" {
		q = `SELECT id, tenant, agent, intent, plan, tools, calls, drift, status, started_at, updated_at
		     FROM tasks ORDER BY updated_at DESC LIMIT $1 OFFSET $2`
		args = []any{limit, offset}
	} else {
		q = `SELECT id, tenant, agent, intent, plan, tools, calls, drift, status, started_at, updated_at
		     FROM tasks WHERE tenant = $1 ORDER BY updated_at DESC LIMIT $2 OFFSET $3`
		args = []any{tenant, limit, offset}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("task: list: %w", err)
	}
	defer rows.Close()
	out := make([]*Task, 0, limit)
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, fmt.Errorf("task: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("task: rows iter: %w", err)
	}
	return out, nil
}
