# Architecture

This document is the orientation for engineers landing on the
gateway docs folder. It describes IntentGate as a whole — the
mental model, the request and response pipelines, the trust
boundary, the audit chain, and the design decisions behind them —
before any individual check is read in depth.

Each check has its own dedicated doc (`05`–`10`) covering wire
format, configuration, failure semantics, and threat-model
detail. This page is the map; those docs are the territory.

---

## 1. The model in one paragraph

IntentGate is a **bidirectional inspection proxy**. It sits between
an AI agent and the tools that agent calls. Every `tools/call`
request flows through a request pipeline before reaching the
upstream tool, and every response flows through a response pipeline
before reaching the agent. Each pipeline is a sequence of
independent checks; each check has its own JSON-RPC error code so
downstream consumers can branch on the failure mode. The whole
thing is a single Go binary — checks run in-process, no sidecars,
no extra network hops on the critical path. The five-check
authorization core (capability, intent, provenance, policy, budget)
completes in sub-2 ms p95; the full bidirectional round-trip
including upstream and response inspection targets sub-3 ms p95.

---

## 2. The trust boundary

```
┌─────────────────────────────────────────────────────────────────┐
│  Zone 3 — no trust                                              │
│  User prompts · retrieved web content · RAG documents           │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Zone 2 — customer's application tier (medium trust)            │
│  Agent runtime · LLM provider · tool servers · MCP endpoints    │
└──────────────────────────┬──────────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  Zone 1 — customer-managed control plane (highest trust)        │
│  IntentGate gateway · Pro Console · audit chain · policy bundle │
│  · master key · admin token                                     │
└─────────────────────────────────────────────────────────────────┘
```

The gateway is the enforcement point between Zone 1 and Zone 2.
Zone 3 inputs (a user's prompt, a web page the agent retrieved,
text returned by a tool that wraps an LLM) cannot affect a
privileged tool without first flowing through the gateway's
checks. This is the architectural premise of the product, and
the reason the gateway lives where it lives — close enough to
each tool call to inspect it, far enough from the agent runtime
to be unaffected if the agent runtime is compromised.

The threat model in full is in the Vendor Security Pack §1 (under
NDA). The public-facing version is at
[intentgate.app/owasp](https://intentgate.app/owasp).

---

## 3. The request pipeline

The agent presents a `tools/call` to `POST /v1/mcp` with a
capability token in the `Authorization: Bearer` header and a
declared intent in the `X-Intent-Prompt` header. The gateway runs
the request through a sequence of independent checks. Any check
can deny; the first denial short-circuits the rest and writes one
audit row describing the verdict.

The order, exactly as wired in `internal/handlers/mcp.go`:

```
agent ─▶ capability ─▶ intent ─▶ provenance ─▶ policy ─▶ budget ─▶ PII (out) ─▶ tenant scope ─▶ [forward via fault isolation] ─▶ upstream
                                  (opt-in)
```

| Check          | What it verifies                                              | Code   | Source                            |
|----------------|---------------------------------------------------------------|--------|-----------------------------------|
| capability     | HMAC token signature + caveats (tool_allow, exp, agent_lock)  | -32010 | `internal/capability/`            |
| intent         | Declared intent's `allowed_tools` includes the requested tool | -32011 | `internal/extractor/` + handler   |
| provenance     | Memory entries shaping this call are HMAC-signed (opt-in)     | -32014 | `internal/provenance/`            |
| policy         | Rego decision: allow / block / escalate                       | -32012 | `internal/policy/`                |
| budget         | Per-token call counter remains under `max_calls`              | -32013 | `internal/budget/`                |
| PII (outbound) | Argument values scrubbed for PII + credentials                | -32015 | `internal/pii/` (request side)    |
| tenant scope   | Vector / RAG calls scoped to the token's tenant claim         | -32017 | `internal/tenantscope/`           |
| fault isolation| Bulkhead semaphore + circuit breaker around the forward       | -32018 | `internal/faultisolation/`        |

A few non-obvious properties worth knowing before reading the
per-check docs:

**Capability verification is HMAC, not asymmetric.** No public-key
verification, no JWKS fetch, no token introspection round-trip.
The gateway verifies tokens in-process against its master key.
This is the property that lets the whole authorization core
finish in sub-2 ms p95. The trade-off (the gateway needs the
master key in memory) is discussed in `10-api-authentication.md`.

**Provenance is opt-in and default off.** Enable per-deployment
via `INTENTGATE_PROVENANCE_ENABLED=true`. When unset, the stage
is a transparent pass-through — no signing-key derivation, no
HMAC verification, no measurable overhead. See
`05-memory-provenance.md` for the wire contract.

**Policy can escalate; the other checks only allow or block.** An
`escalate` verdict pauses the request and queues it for human
approval via the operator console. Capability, intent, budget,
tenant scope, and PII filter have no human-in-the-loop semantic —
they either pass or fail.

**PII filter runs before tenant scope on the outbound side.**
Intentional: any PII the agent is trying to leak should be scanned
before the call is gated on tenant scope, so that a tenant-scope
violation doesn't accidentally suppress a PII-filter audit row.

**Fault isolation is the last gate before the network.** A breaker
open on the billing tool fails fast at `-32018` without contacting
upstream; a healthy tool's calls pass through unaffected.
Independent state per tool. See `09-fault-isolation.md` for the
bulkhead and breaker state machines.

---

## 4. The upstream forward

If every check passes, the gateway forwards the request to the
configured upstream tool server (typically an MCP server, but any
HTTP endpoint configured per tool). The forward executes inside
the fault-isolation context acquired in the previous step:

- The bulkhead semaphore is held for the duration of the forward.
- Upstream timeouts, 5xx responses, and connection failures count
  as `OutcomeFailure` against the breaker for that tool.
- 2xx responses count as `OutcomeSuccess`.

There is no caching at the gateway layer. Every forwarded request
is a fresh upstream call; idempotency is the upstream's concern.
The gateway adds a correlation header (`X-IntentGate-Request-ID`)
and forwards the body and the rest of the headers unchanged.

If the upstream returns a JSON-RPC error, the gateway preserves
the upstream's error envelope unchanged — the gateway's own
`-32010` through `-32018` codes are reserved for verdicts the
gateway itself produced.

---

## 5. The response pipeline

The upstream's response runs through a second sequence of checks
before the bytes reach the agent.

```
upstream ─▶ PII (in) ─▶ output schema ─▶ agent
```

| Check         | What it does                                              | Code   | Source                            |
|---------------|-----------------------------------------------------------|--------|-----------------------------------|
| PII (inbound) | Response body scrubbed for PII + credentials              | -32015 | `internal/pii/` (response side)   |
| Output schema | Response validated against per-tool JSON-Schema shape     | -32016 | `internal/outputschema/`          |

The PII filter is the same engine, same eighteen built-in classes
(nine PII + nine credential families), same three actions
(redact / block / escalate), and the same per-tenant SHA-256
audit chain as the request side. The audit row's `direction`
field distinguishes which way a given match fired. Counts only;
matched values are never persisted. The bidirectional symmetry is
the architectural shift that turned the gateway from a one-way
authorization proxy into a true inspection proxy — see
`06-pii-filter.md` for the wire contract and the credential
class list.

Output schema validation enforces a JSON-Schema-subset shape
declared per tool by the operator. Three actions:

- `allow` — observation only; the response passes through, counts
  land in audit.
- `strip` (default) — undeclared fields are removed; wrong-type
  scalars are dropped; the cleaned response reaches the agent.
- `block` — any violation refuses the response at `-32016`; the
  agent sees a JSON-RPC error.

Schemas live in a single JSON file mounted at
`INTENTGATE_OUTPUT_SCHEMAS_PATH`. The gateway fail-CLOSES on a
missing or malformed file — it will refuse to start rather than
silently disable response inspection. See `07-output-schema.md`.

The response pipeline targets sub-1 ms p95 added latency over the
upstream forward itself. Measured: PII filter ~32 µs no-match /
~140 µs five-match on a 4 KB response (M2, Go 1.22); schema
validation ~100 µs with compiled schemas cached.

---

## 6. The audit chain

Every decision from any check, in either direction, writes one row
to a per-tenant hash-chained log in Postgres. Each row carries:

```
tenant_id   agent_id   tool_name
check_stage  direction  decision  reason
counts       prev_hash  row_hash
```

Where:

- `check_stage` is one of `capability | intent | provenance |
  policy | budget | tenant_scope | pii | output_schema |
  fault_isolation`.
- `direction` is `request` or `response`. PII filter is the only
  check that appears in both directions; the others are
  single-direction by construction.
- `decision` is `allow | block | escalate | redact`.
- `counts` is a per-class match count (e.g. `{"email": 5,
  "iban": 1}`). **Never matched values.**
- `prev_hash` is the SHA-256 of the previous row in this tenant's
  chain; `row_hash` is the SHA-256 of this row (including
  `prev_hash`). The chain is per-tenant, not gateway-wide.

The per-tenant chain has three useful properties:

1. **Master-key rotation does not invalidate the chain.** The chain
   is SHA-256 over the row's contents, not HMAC of the master key.
   A customer can rotate `INTENTGATE_MASTER_KEY` without breaking
   audit replay.
2. **Tenant isolation.** A compromise of one tenant's audit table
   does not affect any other tenant's chain integrity.
3. **Parallel verification.** `POST /v1/admin/audit/verify` runs
   per-tenant in parallel.

### Counts only, never values

This is the load-bearing principle. A PII filter match for five
emails and one IBAN writes `counts: {"email": 5, "iban": 1}` —
the matched strings exist transiently in the gateway's process
memory during scanning and are then garbage-collected. The chain
contains no PII.

Operators who need to see matched content consult the upstream
tool's own logs, where the data already lives under the upstream's
own access controls. The gateway is not a secondary store for
sensitive content; it is an inspection point that emits evidence
of inspection.

For querying, replay, and chain verification, see
`04-audit-verify.md`.

---

## 7. Why in-process, not a sidecar

The obvious alternative is to push response-side inspection to a
sidecar — Presidio for PII, a separate schema validator service,
a ZScaler-style DLP appliance. Three reasons we keep everything
in-process:

**Latency.** A sidecar HTTP round-trip is ~5 ms at best on the
same host; in-process Go regex and JSON-Schema validation are two
orders of magnitude lower. With multiple request-side checks and
two response-side checks sharing a sub-3 ms p95 budget, any single
sidecar would consume the entire budget on its own.

**Audit cohesion.** All checks need to land in the same
tamper-evident chain, in causal order, with a single `prev_hash`
link between successive rows. A sidecar adds a second audit
surface that the operator now has to correlate across when
investigating an incident — and that cross-surface correlation is
exactly the kind of post-hoc reconstruction that subtle tampering
can hide in.

**Deployment simplicity.** One container, one Helm value to flip
each check on or off. Customers who *want* a sidecar (Presidio,
a custom ML PHI classifier) can layer one in front of or behind
IntentGate — the model doesn't preclude that. It just doesn't
require it.

For deployments that genuinely need ML-based detection beyond
what regex + JSON-Schema can deliver, a `RemoteCheck` adapter that
calls out to a customer-operated HTTP endpoint per response is
tracked on the response-inspection roadmap. Out of scope for the
in-process checks today.

---

## 8. What this doesn't do

The gateway is a runtime authorization control. It is **not**:

**A content filter** for the model's output. The gateway sits
between the agent's tool calls and the tools, not in the model's
token stream. Lakera, NeMo Guardrails, Robust Intelligence
address that layer.

**A model evaluation tool.** The gateway does not score the
model's factuality. Patronus, Galileo, Arize address LLM09
(misinformation). The policy `escalate` path can route
high-stakes outputs to a human approver but does not validate
truthfulness.

**An identity provider.** The gateway integrates with the
customer's OIDC IdP for operator login (see
`10-api-authentication.md`) and with SCIM 2.0 for provisioning.
It does not issue identity tokens for end users.

**A code-execution sandbox.** If a tool is a code interpreter,
the customer is responsible for sandboxing it (gVisor,
Firecracker microVMs, separate pods with no host network). The
gateway authorizes the call into the sandbox; sandbox integrity
is the customer's.

**A supply-chain analyser.** Signed releases and SBOMs are
published for the gateway, SDKs, helm chart, and intent extractor
(Apache 2.0). The gateway does not analyse the customer's wider
stack — that's SCA tooling territory.

These boundaries are deliberate. Mapping each threat category to
the appropriate control layer prevents both over-claiming and
over-buying. The full OWASP coverage map (14 direct mitigations,
1 partial — LLM09, 5 out of scope) is at
[intentgate.app/owasp](https://intentgate.app/owasp).

---

## 9. Where to go from here

Concrete next reads, in the order most engineers will want them:

- [`01-quickstart.md`](./01-quickstart.md) — gateway running in 5
  minutes against the bundled lab.
- [`02-first-policy.md`](./02-first-policy.md) — author a Rego
  policy against the live policy engine.
- [`03-first-agent.md`](./03-first-agent.md) — wire an agent
  through the Python SDK.
- [`04-audit-verify.md`](./04-audit-verify.md) — query the audit
  chain and run integrity verification.

Per-check depth:

- [`05-memory-provenance.md`](./05-memory-provenance.md) — AGENT06,
  opt-in fifth check.
- [`06-pii-filter.md`](./06-pii-filter.md) — LLM02, bidirectional
  (the load-bearing example of the inspection-proxy model).
- [`07-output-schema.md`](./07-output-schema.md) — LLM05, response
  side.
- [`08-tenant-scope.md`](./08-tenant-scope.md) — LLM08, request
  side.
- [`09-fault-isolation.md`](./09-fault-isolation.md) — AGENT08,
  around the upstream forward.
- [`10-api-authentication.md`](./10-api-authentication.md) —
  capability tokens, OIDC, SCIM, and where OAuth fits.

If a section of this document drifts from the code in
`internal/handlers/mcp.go`, the code is the source of truth and
this document is the bug. File an issue with the heading
`[docs/architecture]`.
