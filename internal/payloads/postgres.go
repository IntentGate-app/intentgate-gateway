package payloads

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

// PostgresStore is the durable, multi-replica-safe payload store.
//
// Unlike MemoryStore this is safe behind more than one gateway replica: a
// response captured on one node is readable from any other. With the in-memory
// store that read would miss, and a miss is indistinguishable from expiry,
// which is a silent wrong answer rather than an error.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgres applies the migration and returns the store, using a pool the
// caller already owns.
func NewPostgres(ctx context.Context, pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, errors.New("payloads: nil pool")
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, fmt.Errorf("payloads: migrate: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

// NewPostgresFromDSN opens its own pool. Mirrors auditstore, which also owns
// its pool privately rather than sharing one across packages: a shared pool
// would mean payload writes and audit writes compete for the same connections,
// and payload capture is the one that must never slow the decision path.
//
// The pool is deliberately small. Capture is a side effect of a request that
// has already been decided, so it should not be able to starve anything else
// of connections under load.
func NewPostgresFromDSN(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("payloads: postgres DSN is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("payloads: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 5
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("payloads: connect: %w", err)
	}
	return NewPostgres(ctx, pool)
}

// Close releases the pool. Only meaningful for a store built by
// NewPostgresFromDSN; harmless otherwise.
func (p *PostgresStore) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

func (p *PostgresStore) Put(ctx context.Context, rec Record) error {
	if rec.EventID == "" {
		return errors.New("payloads: empty event id")
	}
	if rec.ExpiresAt.IsZero() {
		// Refuse rather than default. A row with no expiry is a permanent copy
		// of customer data created by an oversight, and it would be invisible
		// until someone went looking years later.
		return errors.New("payloads: refusing to store a payload with no expiry")
	}
	if rec.CapturedAt.IsZero() {
		rec.CapturedAt = time.Now().UTC()
	}
	// ON CONFLICT DO NOTHING: first write wins. A retried capture must not be
	// able to replace the body whose hash is already on the audit event.
	const q = `
		INSERT INTO agent_call_payloads
			(event_id, tenant, agent_id, tool, raw_sha256, raw_bytes,
			 body, redacted, captured_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (tenant, event_id) DO NOTHING`
	_, err := p.pool.Exec(ctx, q,
		rec.EventID, rec.Tenant, rec.AgentID, rec.Tool,
		rec.RawSHA256, rec.RawBytes,
		rec.Body, rec.Redacted, rec.CapturedAt, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("payloads: put: %w", err)
	}
	return nil
}

func (p *PostgresStore) Get(ctx context.Context, tenant, eventID string) (Record, error) {
	// expires_at > now() is in the WHERE clause, not checked after the read.
	// Retention that depends on a sweeper having run is not retention.
	const q = `
		SELECT event_id, tenant, agent_id, tool, raw_sha256, raw_bytes,
		       body, redacted, captured_at, expires_at
		  FROM agent_call_payloads
		 WHERE tenant = $1 AND event_id = $2 AND expires_at > now()`
	var r Record
	err := p.pool.QueryRow(ctx, q, tenant, eventID).Scan(
		&r.EventID, &r.Tenant, &r.AgentID, &r.Tool, &r.RawSHA256, &r.RawBytes,
		&r.Body, &r.Redacted, &r.CapturedAt, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("payloads: get: %w", err)
	}
	return r, nil
}

func (p *PostgresStore) Purge(ctx context.Context, now time.Time) (int, error) {
	const q = `DELETE FROM agent_call_payloads WHERE expires_at <= $1`
	tag, err := p.pool.Exec(ctx, q, now)
	if err != nil {
		return 0, fmt.Errorf("payloads: purge: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
