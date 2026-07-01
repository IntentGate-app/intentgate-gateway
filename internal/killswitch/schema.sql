-- Kill-switch entries. One active kill per (scope, tenant, value).
--
-- scope is 'global' | 'tenant' | 'agent'. For global, tenant and value
-- are empty strings; for tenant, value is empty; for agent, both are
-- set. The composite primary key gives idempotent Engage and an O(1)
-- keyed lookup on the hot path. IF NOT EXISTS keeps the migration
-- idempotent across restarts, matching the revocation store.
CREATE TABLE IF NOT EXISTS kill_switch (
    scope   TEXT        NOT NULL,
    tenant  TEXT        NOT NULL DEFAULT '',
    value   TEXT        NOT NULL DEFAULT '',
    reason  TEXT        NOT NULL DEFAULT '',
    set_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    set_by  TEXT        NOT NULL DEFAULT '',
    PRIMARY KEY (scope, tenant, value)
);

CREATE INDEX IF NOT EXISTS kill_switch_set_at_idx ON kill_switch (set_at DESC);
