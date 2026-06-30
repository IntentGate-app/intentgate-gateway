package credentials

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// schemaSQL is applied at startup; IF NOT EXISTS keeps it idempotent so
// no migration tool is needed. Values are stored encrypted (never
// plaintext) — the column holds base64(nonce||ciphertext).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS upstream_credentials (
	tool            TEXT PRIMARY KEY,
	value_encrypted TEXT NOT NULL,
	updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// PostgresStore persists per-tool upstream credentials, encrypted at
// rest with AES-256-GCM, so console-managed changes survive restarts
// and can be shared across gateway replicas.
type PostgresStore struct {
	pool   *pgxpool.Pool
	sealer *sealer
}

// NewPostgresStore connects, pings, migrates, and returns a store. The
// caller owns it and must Close it on shutdown.
func NewPostgresStore(ctx context.Context, dsn string, encKey []byte) (*PostgresStore, error) {
	if dsn == "" {
		return nil, errors.New("credentials: postgres DSN is required")
	}
	seal, err := newSealer(encKey)
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("credentials: parse DSN: %w", err)
	}
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 5
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("credentials: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("credentials: ping: %w", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("credentials: migrate: %w", err)
	}
	return &PostgresStore{pool: pool, sealer: seal}, nil
}

// Close releases the connection pool.
func (p *PostgresStore) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

// loadAll returns tool -> "Header: value" (decrypted).
func (p *PostgresStore) loadAll(ctx context.Context) (map[string]string, error) {
	rows, err := p.pool.Query(ctx, `SELECT tool, value_encrypted FROM upstream_credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var tool, enc string
		if err := rows.Scan(&tool, &enc); err != nil {
			return nil, err
		}
		plain, err := p.sealer.open(enc)
		if err != nil {
			return nil, fmt.Errorf("credentials: decrypt %q: %w", tool, err)
		}
		out[tool] = plain
	}
	return out, rows.Err()
}

// upsert encrypts and writes a tool's credential.
func (p *PostgresStore) upsert(ctx context.Context, tool, raw string) error {
	enc, err := p.sealer.seal(raw)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO upstream_credentials (tool, value_encrypted, updated_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (tool) DO UPDATE
		   SET value_encrypted = EXCLUDED.value_encrypted, updated_at = now()`,
		tool, enc)
	return err
}

// remove deletes a tool's credential.
func (p *PostgresStore) remove(ctx context.Context, tool string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM upstream_credentials WHERE tool = $1`, tool)
	return err
}
