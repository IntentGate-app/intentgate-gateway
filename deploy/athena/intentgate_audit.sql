-- ─────────────────────────────────────────────────────────────────────
-- IntentGate audit table — Athena / Glue catalog
-- ─────────────────────────────────────────────────────────────────────
--
-- Reads the gzipped NDJSON the gateway's S3 sink writes (gateway v1.7+).
-- Object layout under the bucket:
--
--   audit/year=YYYY/month=MM/day=DD/hour=HH/<gateway-id>-<rfc3339>-<rand>.ndjson.gz
--
-- Partition projection is enabled so Athena infers partitions from the
-- prefix template at query time. No MSCK REPAIR. No per-day partition
-- registration. Queries that filter on year/month/day prune
-- automatically.
--
-- ─────────────────────────────────────────────────────────────────────
-- Before running:
--   1. Replace `your-bucket` below with your bucket name (two places).
--   2. Replace `intentgate` with your preferred database name if it
--      already exists, or run `CREATE DATABASE intentgate;` first.
--   3. Adjust projection.year.range if you started shipping audit
--      before 2026 or expect to retain past 2099.
-- ─────────────────────────────────────────────────────────────────────

CREATE EXTERNAL TABLE IF NOT EXISTS intentgate.audit (
  ts                       string,        -- RFC3339Nano timestamp
  event                    string,        -- event type, e.g. "intentgate.tool_call"
  schema_version           string,        -- audit envelope version
  decision                 string,        -- "allow" | "block" | "escalate"
  check                    string,        -- "capability" | "intent" | "policy" | "budget" | "upstream" | "pii" | "output_schema" | "tenant_scope" | "provenance" | ""
  reason                   string,        -- human-readable explanation when blocked or escalated
  tenant                   string,        -- tenant identifier
  agent_id                 string,        -- subject from the capability token
  session_id               string,        -- agent runtime session
  tool                     string,        -- resolved tool name
  arg_keys                 array<string>, -- structural argument keys (no values)
  arg_values               map<string, string>, -- optional redacted argument values (opt-in per policy)
  capability_token_id      string,        -- JTI of the presenting token
  root_capability_token_id string,        -- JTI of the chain root (delegation)
  caveat_count             int,           -- number of caveats bound to the token
  pending_id               string,        -- approval queue ID when escalate
  decided_by               string,        -- operator identity who decided an escalation
  intent_summary           string,        -- one-line user intent captured by extractor
  latency_ms               bigint,        -- gateway-internal authorization latency
  remote_ip                string,        -- caller IP
  upstream_status          int,           -- HTTP status from the upstream tool server
  requires_step_up         boolean,       -- decision required a fresh-factor token
  elevation_id             string         -- JIT elevation that authorized this call
)
PARTITIONED BY (
  year  string,
  month string,
  day   string,
  hour  string
)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
       OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://your-bucket/audit/'
TBLPROPERTIES (
  'projection.enabled'        = 'true',
  'projection.year.type'      = 'integer',
  'projection.year.range'     = '2026,2099',
  'projection.month.type'     = 'integer',
  'projection.month.range'    = '1,12',
  'projection.month.digits'   = '2',
  'projection.day.type'       = 'integer',
  'projection.day.range'      = '1,31',
  'projection.day.digits'     = '2',
  'projection.hour.type'      = 'integer',
  'projection.hour.range'     = '0,23',
  'projection.hour.digits'    = '2',
  'storage.location.template' = 's3://your-bucket/audit/year=${year}/month=${month}/day=${day}/hour=${hour}/'
);

-- ─────────────────────────────────────────────────────────────────────
-- Example queries — see deploy/athena/examples/ for more.
-- ─────────────────────────────────────────────────────────────────────

-- Every block in the last 24 hours for one tenant:
--   SELECT ts, tool, check, reason, agent_id
--   FROM intentgate.audit
--   WHERE year = '2026' AND month = '06' AND day BETWEEN '13' AND '14'
--     AND tenant = 'acme-corp' AND decision = 'block'
--   ORDER BY ts DESC;

-- Count of escalations by rule, full historical archive:
--   SELECT reason, COUNT(*) AS n
--   FROM intentgate.audit
--   WHERE decision = 'escalate'
--   GROUP BY reason
--   ORDER BY n DESC;
