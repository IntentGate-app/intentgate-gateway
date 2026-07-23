# Federation deployment & environment checklist

Split-plane federation: one **control plane** (Console Pro) manages many
**data-plane nodes** (gateways in each cloud / region / on-prem). Telemetry goes
up, policy (incl. global STOP ALL) goes down, payloads never leave a node.

---

## 0. Build & test (before pushing)

**Gateway (Go):**
```bash
cd gateway
go build ./...
go test ./internal/federation/
```
**Console (TypeScript):**
```bash
cd console-pro
npx tsc --noEmit        # already green
npm run build
```

---

## 1. Control plane (Console Pro)

The federation store lives in the console's SCIM Postgres. Nothing else is
required to turn it on.

| Env var | Required | Notes |
|---------|----------|-------|
| `SCIM_DATABASE_URL` | yes | Postgres DSN. The `console_federation_*` tables migrate automatically on first use. Without it, `/federation` shows an honest "not configured" state and the ingest/directive endpoints return 503. |

Endpoints exposed by the console:
- `POST /api/federation/rollup` — telemetry ingest (node → console).
- `GET  /api/federation/directive` — directive poll (node → console).

Both authenticate the node by its bearer token; neither is reachable without a
registered, non-revoked node token.

---

## 2. Register each node (Console Pro → Federation)

1. Sign in as **admin**, open **Federation → Control plane** (`/federation`).
2. **Register a data-plane node**: enter a node id (e.g. `ali-cn-shanghai`),
   optional name and domain (domain groups nodes in the unified view, e.g.
   `cn-shanghai`).
3. Copy the **bearer token** and **signing key** shown once — they are not
   stored and cannot be shown again.

---

## 3. Data plane (each gateway node)

Set these on the node, using the values from step 2. `INTENTGATE_POSTGRES_URL`
(already used for the audit store) also backs the local kill switch, so a global
stop survives a restart.

| Env var | Required | Default | Notes |
|---------|----------|---------|-------|
| `INTENTGATE_NODE_ID` | yes | — | Must match the id registered in step 2. |
| `INTENTGATE_FEDERATION_CONTROL_URL` | up channel | — | Full ingest URL, e.g. `https://console.example.com/api/federation/rollup`. |
| `INTENTGATE_FEDERATION_TOKEN` | yes | — | Bearer token from step 2 (used for both push and directive poll). |
| `INTENTGATE_FEDERATION_SIGNING_KEY` | recommended | — | Signing key from step 2. Signs rollups; verifies directives. Strongly recommended (mandatory for air-gapped import). |
| `INTENTGATE_FEDERATION_TENANT` | no | "" | Restrict the rollup to one trust domain. |
| `INTENTGATE_FEDERATION_INTERVAL_S` | no | 60 | Rollup push interval. |
| `INTENTGATE_FEDERATION_DIRECTIVE_URL` | down channel | — | Full directive URL, e.g. `https://console.example.com/api/federation/directive`. Enables the STOP ALL poll. |
| `INTENTGATE_FEDERATION_DIRECTIVE_INTERVAL_S` | no | 15 | How fast a global stop reaches this node. |
| `INTENTGATE_FEDERATION_ROLLUP_DIR` | air-gapped only | — | Write signed rollups to this dir instead of/with pushing, for offline import. |

**Minimum to be fully managed** (up + down): `INTENTGATE_NODE_ID`,
`INTENTGATE_FEDERATION_CONTROL_URL`, `INTENTGATE_FEDERATION_DIRECTIVE_URL`,
`INTENTGATE_FEDERATION_TOKEN`, `INTENTGATE_FEDERATION_SIGNING_KEY`.

**Air-gapped node:** omit the two URLs, set `INTENTGATE_NODE_ID`,
`INTENTGATE_FEDERATION_SIGNING_KEY`, and `INTENTGATE_FEDERATION_ROLLUP_DIR`.
Carry the written JSON files to the console and import them under
**Federation → Import an offline rollup**.

---

## 4. Verify

1. Start the node; the log should show `federation push enabled` and
   `federation directive poll enabled`.
2. In `/federation`, within one interval the node's **Windows** count and latest
   decision counts populate, and its domain appears in **Governance domains**.
   The signature column should read **verified** (signing key set).
3. **Test STOP ALL** in a lab: click **STOP ALL AGENTS**, confirm. Within
   `DIRECTIVE_INTERVAL_S` the node logs `GLOBAL KILL ENGAGED` and begins blocking
   tool calls (kill switch, global scope). Click **Release global stop**; the
   node logs the release and resumes.

---

## 5. Rollback

Federation is fully opt-in: unset the federation env vars on a node and it stops
pushing/polling with no other effect. On the console, an unset
`SCIM_DATABASE_URL` disables the whole feature. No hot path changes when
federation is off.
