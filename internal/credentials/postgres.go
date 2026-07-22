package credentials

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// migrateStmts are applied at startup, each idempotent so no migration
// tool is needed. Values are stored encrypted (never plaintext) — the
// column holds base64(nonce||ciphertext). owner and expires_at are added
// with ALTER ... IF NOT EXISTS so an existing table upgrades in place.
var migrateStmts = []string{
	`CREATE TABLE IF NOT EXISTS upstream_credentials (
		tool            TEXT PRIMARY KEY,
		value_encrypted TEXT NOT NULL,
		updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
	)`,
	`ALTER TABLE upstream_credentials ADD COLUMN IF NOT EXISTS owner TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE upstream_credentials ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
}

// PostgresStore persists per-tool upstream credentials, encrypted at
// rest with AES-256-GCM, so console-managed changes survive restarts
// and can be shared across gateway replicas.
type PostgresStore struct {
	pool   *pgxpool.Pool
	sealer *sealer
}

// persistedCred is one decrypted row with its governance metadata.
type persistedCred struct {
	raw       string
	rotatedAt time.Time
	owner     string
	expiresAt time.Time // zero when NULL
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
	for _, stmt := range migrateStmts {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			pool.Close()
			return nil, fmt.Errorf("credentials: migrate: %w", err)
		}
	}
	return &PostgresStore{pool: pool, sealer: seal}, nil
}

// Close releases the connection pool.
func (p *PostgresStore) Close() {
	if p != nil && p.pool != nil {
		p.pool.Close()
	}
}

// loadAllMeta returns tool -> decrypted credential + governance metadata.
func (p *PostgresStore) loadAllMeta(ctx context.Context) (map[string]persistedCred, error) {
	rows, err := p.pool.Query(ctx,
		`SELECT tool, value_encrypted, updated_at, owner, expires_at FROM upstream_credentials`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]persistedCred{}
	for rows.Next() {
		var tool, enc, owner string
		var updatedAt time.Time
		var expiresAt *time.Time
		if err := rows.Scan(&tool, &enc, &updatedAt, &owner, &expiresAt); err != nil {
			return nil, err
		}
		plain, err := p.sealer.open(enc)
		if err != nil {
			return nil, fmt.Errorf("credentials: decrypt %q: %w", tool, err)
		}
		pc := persistedCred{raw: plain, rotatedAt: updatedAt, owner: owner}
		if expiresAt != nil {
			pc.expiresAt = *expiresAt
		}
		out[tool] = pc
	}
	return out, rows.Err()
}

// upsertMeta encrypts and writes a tool's credential together with its
// owner and optional expiry, stamping updated_at as the rotation time.
func (p *PostgresStore) upsertMeta(ctx context.Context, tool, raw, owner string, expiresAt time.Time) error {
	enc, err := p.sealer.seal(raw)
	if err != nil {
		return err
	}
	var exp *time.Time
	if !expiresAt.IsZero() {
		exp = &expiresAt
	}
	_, err = p.pool.Exec(ctx,
		`INSERT INTO upstream_credentials (tool, value_encrypted, updated_at, owner, expires_at)
		 VALUES ($1, $2, now(), $3, $4)
		 ON CONFLICT (tool) DO UPDATE
		   SET value_encrypted = EXCLUDED.value_encrypted,
		       updated_at = now(),
		       owner = EXCLUDED.owner,
		       expires_at = EXCLUDED.expires_at`,
		tool, enc, owner, exp)
	return err
}

// remove deletes a tool's credential.
func (p *PostgresStore) remove(ctx context.Context, tool string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM upstream_credentials WHERE tool = $1`, tool)
	return err
}
