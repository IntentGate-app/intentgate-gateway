-- Bound tasks. One row per (tenant, task id). Plan is the declared
-- allowed-tool envelope captured at task start; tools is the distinct
-- set actually used. Drift accumulates across the session. IF NOT
-- EXISTS keeps the migration idempotent across restarts.
CREATE TABLE IF NOT EXISTS tasks (
    id         TEXT        NOT NULL,
    tenant     TEXT        NOT NULL DEFAULT '',
    agent      TEXT        NOT NULL DEFAULT '',
    intent     TEXT        NOT NULL DEFAULT '',
    plan       TEXT[]      NOT NULL DEFAULT '{}',
    tools      TEXT[]      NOT NULL DEFAULT '{}',
    calls      INTEGER     NOT NULL DEFAULT 0,
    drift      INTEGER     NOT NULL DEFAULT 0,
    status     TEXT        NOT NULL DEFAULT 'active',
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, id)
);

CREATE INDEX IF NOT EXISTS tasks_updated_at_idx ON tasks (updated_at DESC);
