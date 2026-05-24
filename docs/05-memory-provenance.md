# Memory Provenance (AAI03 Defense)

**Status:** Shipped 2026-05-24 · Opt-in via `INTENTGATE_PROVENANCE_ENABLED=true`
**Pipeline position:** Check 3, between intent and policy
**Audience:** Engineers extending or maintaining the gateway / SDKs

This doc explains the *implementation* of memory provenance. For the
strategic design rationale, see `memos/aai03-memory-provenance-design.md`
in the operator's working tree. For customer-facing claims, see Section 1
of `docs/IntentGate-Vendor-Security-Pack.docx`.

---

## The threat

The sophisticated case of OWASP Agentic AI Top 10 AAI03: an attacker
has write access to the agent's memory store (vector DB, RAG corpus,
scratchpad) but has NOT compromised the user's prompt channel and has
NOT stolen a capability token. The attacker plants a memory entry
crafted to align with the user's prompt (so the intent check passes)
while corrupting the resulting tool call's *arguments* in a subtle way.

Example: user says "send the monthly invoice to our usual vendor."
The agent reads memory for the vendor's banking details. The attacker
has swapped the account number. The capability check passes (the
agent has `transfer_funds` scope), the intent check passes (the prompt
mentions invoice + vendor), policy and budget pass if the amount is in
range. Money goes to the attacker.

The intent check alone cannot catch this — the prompt and tool name
are consistent. The defense has to verify that the memory inputs
shaping the call are themselves trustworthy.

---

## Runtime architecture

![Three-phase runtime architecture: mint phase derives a memory signing key from the capability token via HKDF; write phase has the agent sign memory entries locally with HMAC-SHA256 and store in the customer's memory backend; tool-call phase has the agent attach the signed envelopes in the X-Intent-Memory-Provenance header, where the gateway re-derives the session key, verifies each HMAC, and walks the per-session hash chain.](./diagrams/aai03-memory-provenance-architecture.svg)

Three phases, no new runtime component:

1. **Mint** — `igctl mint --with-memory-signing-key` derives a per-session 32-byte signing key from the master key via HKDF-SHA256 (salt = capability token's `jti`). The key is bundled into the mint response, never persisted server-side, and travels under the same trust boundary as the capability token itself.
2. **Write** — the agent's SDK wraps each memory entry in an envelope (`id`, `session_id`, `timestamp`, `prev_hash`, `data`, `hmac`), signs it locally with the per-session key, and stores the envelope in the customer's existing memory backend. The gateway is not in the write path.
3. **Tool call** — the agent attaches the envelopes that backed the call in an `X-Intent-Memory-Provenance` header. The gateway re-derives the session key from the bearer token, recomputes the HMAC over the canonical bytes, walks the hash chain, and either passes the request through to policy or returns `-32014` with a structured audit row naming the failed envelope.

The runtime topology is otherwise identical to a non-provenance deployment — one binary, one capability-token trust boundary, one audit chain.

---

## Wire contract (the part you cannot break)

Three primitives, in this exact form:

1. **Key derivation.** `memory_signing_key = HKDF-SHA256(ikm =
   master_key, salt = capability_token.jti, info =
   "intentgate-memory-v1", length = 32)`. Implemented in
   `internal/provenance.DeriveSessionKey`. Cross-verified against
   Python's `cryptography` library and the SDK KAT tests
   (`sdk-python/tests/test_memory.py::test_hkdf_kat_matches_go_gateway`,
   `sdk-typescript/tests/memory.test.ts::"matches the Go gateway and Python SDK byte-for-byte"`).

2. **Canonical bytes.** Length-prefixed byte concatenation of an
   `Envelope`'s immutable fields in this order:

   ```
   uint32(len(session_id)) || session_id_utf8
   uint32(len(id))         || id_utf8
   uint64(timestamp)       (big-endian)
   uint32(len(prev_hash))  || prev_hash
   uint32(len(data))       || data
   ```

   Implemented in `internal/provenance.Canonical`. NOT JSON — JSON has
   whitespace, key-ordering, and unicode-escape ambiguities that a
   careful canonicalisation can defeat, but a length-prefixed form has
   none of those classes by construction.

3. **Signature.** `HMAC-SHA256(memory_signing_key, Canonical(envelope))`.
   Implemented in `internal/provenance.Sign` and `Verify`. Comparison
   uses `hmac.Equal` for constant-time semantics.

**If you change any of these three, the gateway and every SDK
simultaneously stop being able to verify each other's envelopes.**
The KAT tests across all three implementations catch the simple
case where one implementation drifts; the harder case (changing the
canonical encoding subtly, e.g. switching uint32 to uint64 lengths)
needs a deliberate version bump on `info` ("intentgate-memory-v1" →
"intentgate-memory-v2") and a transition period accepting both.

---

## Pipeline integration

```
Capability → Intent → Provenance → Policy → Budget
   (1)        (2)        (3)         (4)      (5)
```

When `MCPHandlerConfig.ProvenanceEnabled == false` (default), check 3
is a no-op and the gateway runs the familiar four-check pipeline. When
true:

- Request with no `X-Intent-Memory-Provenance` header → check returns
  `summary: "no_header"`, no error. Policy decides whether absence of
  provenance is itself a deny condition (a customer with a high-stakes
  workflow can write an OPA rule that requires provenance for certain
  tools).
- Request with the header → parse base64url → JSON array of wire
  entries → for each entry, decode `data`/`prev_hash`/`hmac` from
  base64url, check `session_id == capability.jti`, build a
  `provenance.Envelope`. Then `VerifyChain(sessionKey, envelopes)`
  walks the per-session hash chain and verifies every HMAC.
- Any failure → `mcp.CodeProvenanceFailed = -32014` with the typed
  reason in the error data field; structured `Check: CheckProvenance`
  audit event emitted.

The handler stage is `runProvenanceCheck` in
`internal/handlers/mcp_provenance.go`. Test coverage in
`internal/handlers/mcp_provenance_test.go` — 14 test cases including
the textbook "swap data, keep HMAC" attack.

---

## SDK side

Both `@netgnarus/intentgate` (TypeScript, `sdk-typescript/src/memory.ts`)
and `intentgate` (Python, `sdk-python/src/intentgate/memory.py`) expose
a `MemoryStore` class with the same shape:

- `new MemoryStore(session_id, memory_signing_key, { write_hook?,
  read_hook? })` — constructor. Customer plugs their backend in via
  the two hooks; fallback in-memory storage if not supplied.
- `store.write(data)` — signs an envelope with the session key,
  stores it (via `write_hook` or the fallback), returns the entry id.
  Auto-tracks the per-session hash chain head.
- `store.read(id)` — fetches and verifies. Returns the envelope or
  throws if HMAC mismatch (the storage-layer tamper case caught at
  the agent's read site rather than the gateway).
- `store.provenance_for([ids])` — produces the wire-format objects
  the SDK packs into the `X-Intent-Memory-Provenance` header.

The signing key arrives at the SDK via the mint endpoint extension:
`POST /v1/admin/mint` with `with_memory_signing_key: true` returns
`memory_signing_key` in the response (base64url, 32 bytes). The SDK
constructor takes the decoded bytes.

---

## Rough edges & TODOs

- **The lab demo card constructs envelopes inline rather than going
  through the SDK** (`console-pro/lib/lab-attacks/scenarios.ts` →
  `signProvenanceEnvelope`). This is intentional — console-pro
  doesn't take a runtime dep on `@netgnarus/intentgate`. If we ever
  add the SDK as a dep we should refactor the lab card to use it for
  consistency.
- **No "tool requires provenance" rule yet in baseline.rego.** A
  customer who turns provenance on and wants to require it for a
  specific tool currently writes the OPA rule themselves. We could
  add a stock `requires_provenance(tool)` helper to the policy package
  if customers ask.
- **Key rotation is tied to capability token rotation.** When the
  capability rotates, the derived signing key rotates with it. Old
  memory entries become unverifiable. There is no grace window logic
  today — a customer doing capability rotation needs to plan for
  re-signing memory entries (or accept that pre-rotation entries are
  no longer usable as provenance). Open question: should the gateway
  accept envelopes signed by any of the last N capability JTIs in the
  same tenant? Adds state; defer until a customer asks.
- **No content-redaction story for OPA inputs.** The provenance check
  hands the full envelope content to OPA so policy authors can write
  argument-value rules. That means the content of memory entries
  appears in audit logs if the customer's OPA rule references them.
  Document this in the policy authoring guide; consider a redaction
  hook if a customer wants to keep content out of audit while still
  authorising on it.
- **Lab gateway runs `build: ../gateway` not the pinned GHCR image
  (1.6.1) because the released image predates this work.** Flip back
  to a pinned image once 1.6.2 is cut with the provenance code. See
  `intentgate-lab/compose.yml`.

---

## Operating it

To enable on a customer deployment:

```yaml
# helm values / docker-compose
environment:
  INTENTGATE_PROVENANCE_ENABLED: "true"
```

To mint a provenance-enabled capability:

```bash
curl -X POST $GATEWAY/v1/admin/mint \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "agent-x",
    "tenant": "acme",
    "tools": ["transfer_funds", "read_invoice"],
    "with_memory_signing_key": true
  }'
```

To verify it works against your gateway from the command line:

```bash
# Mint a token with the signing key
RESP=$(curl -sS -X POST $GATEWAY/v1/admin/mint ...)
TOKEN=$(echo "$RESP" | jq -r .token)
JTI=$(echo "$RESP" | jq -r .jti)
KEY=$(echo "$RESP" | jq -r .memory_signing_key | base64url -d > key.bin)

# (Use the SDK's MemoryStore from here — manual canonical-bytes
# construction in shell is a stamp-collector's project.)
```

For a full end-to-end demo, use the AAI03 card on
`/lab/attacks` of any IntentGate lab deployment with provenance
enabled — it stages a legitimate write, simulates a storage-layer
tamper, and shows the gateway rejecting with `entry 0: hmac
mismatch`.

---

## References

- `internal/provenance/` — gateway-side primitives + tests
- `internal/handlers/mcp_provenance.go` — pipeline stage
- `internal/handlers/admin.go` — mint extension
- `sdk-python/src/intentgate/memory.py` — Python SDK
- `sdk-typescript/src/memory.ts` — TypeScript SDK
- `console-pro/lib/lab-attacks/scenarios.ts` (`memory-poisoning` runner) — lab demo
- `memos/aai03-memory-provenance-design.md` — strategic design doc
- `memos/aai03-memory-provenance-architecture.svg` — runtime architecture diagram
- RFC 5869 — HKDF specification
- RFC 2104 — HMAC specification
