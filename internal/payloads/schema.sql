-- Captured tool and agent-to-agent responses.
--
-- Deliberately a separate table from audit_events, not a column on it.
-- Audit events are hash-chained and forwarded to whatever SIEMs the customer
-- has wired up; response bodies on that event would be copied into every one
-- of them under retention rules written for security telemetry rather than for
-- customer data. Here they have their own lifetime and their own access path.
--
-- Treat every row as sensitive. Reading one is access to customer data and is
-- expected to be role-gated and separately audited by the caller.
--
-- Idempotent migration: applied at gateway startup, a no-op on restart.

CREATE TABLE IF NOT EXISTS agent_call_payloads (
    -- Same id as the audit event that recorded the decision, so "was it
    -- allowed" and "what did it return" always join.
    event_id     TEXT NOT NULL,
    tenant       TEXT NOT NULL DEFAULT '',

    agent_id     TEXT NOT NULL DEFAULT '',
    -- Carries the agent prefix for an agent-to-agent call, so the two
    -- directions are distinguishable without another column.
    tool         TEXT NOT NULL,

    -- Hex SHA-256 of the response as it came off the upstream, BEFORE
    -- redaction. The integrity anchor: it proves which response the agent
    -- received, and the same value is written onto the audit event.
    raw_sha256   TEXT NOT NULL,
    raw_bytes    INTEGER NOT NULL DEFAULT 0,

    -- The REDACTED response, byte-for-byte as the agent received it after the
    -- PII filter and output-schema guard. Storing the raw form would defeat
    -- the point: it would mean unredacted customer data existed at rest.
    body         BYTEA,
    redacted     BOOLEAN NOT NULL DEFAULT FALSE,

    captured_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Capture is short-lived by design. Long enough to investigate an
    -- incident, not long enough to become a second copy of the customer's
    -- database.
    expires_at   TIMESTAMPTZ NOT NULL,

    -- Tenant-scoped primary key. A payload must not be reachable by guessing
    -- an event id from another tenant.
    PRIMARY KEY (tenant, event_id)
);

-- Purge scans by expiry across all tenants.
CREATE INDEX IF NOT EXISTS agent_call_payloads_expires_idx
    ON agent_call_payloads (expires_at);

-- "What did this agent's calls return recently" is the common investigation.
CREATE INDEX IF NOT EXISTS agent_call_payloads_agent_idx
    ON agent_call_payloads (tenant, agent_id, captured_at DESC);
