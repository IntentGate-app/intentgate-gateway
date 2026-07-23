# Federation data-residency review

**Scope.** This document reviews exactly what data crosses the boundary between
an IntentGate **data-plane node** (running inside a customer's own cloud, region,
or on-prem estate) and the **control plane** (IntentGate Console Pro). It exists
to support data-sovereignty obligations — China PIPL/DSL, EU GDPR, private-DC
residency requirements — by making the boundary contents auditable field by
field.

**The golden rule.** Policy goes down, telemetry goes up, but customer payloads
and data never leave the local boundary. Prompts, agent memory, tool arguments,
tool results, and any personal data stay inside the node's cloud/VPC/DC. The
control plane receives only aggregate counts, cardinalities, and hashes.

---

## 1. What crosses the boundary

There are exactly three flows. Two go **up** (node → control plane), both
node-initiated and outbound-only. One goes **down** (control plane → node),
polled by the node over the same outbound path — the control plane never dials
into the node.

| Flow | Direction | Transport | Contents |
|------|-----------|-----------|----------|
| Rollup | up | node-initiated HTTPS POST (or an offline file for air-gapped) | aggregate telemetry, zero payload |
| Directive | down | node-initiated HTTPS GET (poll) | a stop/clear command, no data |
| — | — | — | no other channel exists |

No raw event, no request body, no response body, no argument, no reason string,
no intent text, and no agent/tool/session identifier is transmitted on any flow.

---

## 2. Rollup — field-by-field residency review

The rollup is defined in `federation.go` (`type Rollup`). Every field is either
the node's own identity, a time bound, an integer, or a hash. Reviewed field by
field:

| Field | Type | Residency assessment |
|-------|------|----------------------|
| `version` | constant string | Schema tag. No customer data. |
| `node_id` | operator-chosen label | The node's own name (e.g. `ali-cn-shanghai`), set by the operator. Not customer data. |
| `tenant` | trust-domain label | An IntentGate trust-domain name, operator-configured. Not customer data. |
| `window_from` / `window_to` | RFC3339 timestamps | Time bounds of the aggregation window. No customer data. |
| `generated_at` | RFC3339 timestamp | When the rollup was built. No customer data. |
| `decisions` | 4 integers | Counts of allow/hold/deny/total. Aggregate only. |
| `by_check` | map of string→int | Counts keyed by **IntentGate's own check names** (`capability`, `intent`, `policy`, …) — the gateway's vocabulary, not customer data. |
| `agents` / `tools` / `sessions` | integers | **Cardinalities only** — how many distinct agents/tools/sessions were active, never which ones. The identifiers are counted in local sets that never leave the process (`Summarize`). |
| `audit_head` | hex SHA-256 | A digest over the window's `(event_id, result_hash)` pairs. Both inputs are already opaque (a random id and a SHA-256), and only their hash is transmitted. Lets the control plane detect a duplicate/stale window and lets an auditor cross-check the node's local chain during an on-site review — without any event content leaving. |
| `key_id` | constant string | Identifies the signing key, never the key. |
| `signature` | hex HMAC-SHA256 | Integrity tag over the above. Reveals nothing about payloads. |

**Enforced in code.** `Summarize` reduces each decision to categorical keys,
counts them, and **discards the keys**; only integers survive into the
`Aggregate`. The residency guard test
(`federation_test.go` → `TestRollupCarriesNoRawIdentifiers`) marshals a fully
populated, signed rollup and asserts that none of the raw agent ids, tool names,
session ids, event ids, or result hashes that went into `Summarize`/`WindowDigest`
appear anywhere in the wire form. A change that leaked an identifier would fail
CI.

**Storage.** The control-plane schema (`console_federation_rollups`) has no
column that can hold a payload — only the fields above.

---

## 3. Directive — field-by-field residency review

The directive is the down channel (`directive.go` → `type Directive`). It is a
control command, not data.

| Field | Residency assessment |
|-------|----------------------|
| `version`, `key_id`, `signature` | Schema/integrity metadata. |
| `node_id` | Binds the command to one node (prevents cross-node replay). The node's own label. |
| `stop` | Boolean: engage or release the local kill switch. |
| `scope` | `"global"` or a domain name — operator vocabulary. |
| `reason` | Operator-typed free text (e.g. "incident 4821"). **Operator-authored, not customer data.** |
| `seq`, `issued_at` | Change-detection metadata. |

The directive carries no telemetry and no customer data in either direction.

---

## 4. Air-gapped nodes

An air-gapped node cannot reach the control plane at all. Its gateway writes the
**same zero-payload, signed rollup** to a file
(`INTENTGATE_FEDERATION_ROLLUP_DIR`); an operator carries that file out on media
and imports it at the console, where it is recorded only if its signature
verifies against the node's stored signing key. The residency contents are
identical to §2 — the transport changes, the payload does not.

---

## 5. Residency conclusion

For a node deployed in-region (e.g. Alibaba ACK in Shanghai or Tencent TKE in
Shenzhen), all prompts, agent memory, tool arguments, and tool results remain
100% inside that region. The only bytes that leave are decision counts,
cardinalities, IntentGate check-name counts, timestamps, and SHA-256 hashes,
each HMAC-signed. This is consistent with keeping personal information and
important data inside mainland China under PIPL/DSL and inside a private DC or
EU region under GDPR, because no personal data and no customer payload is part
of any transmitted field.

**Review cadence.** Re-run this review whenever `type Rollup` or `type Directive`
gains a field. The residency guard test is the automated backstop; this document
is the human-readable rationale that must be updated alongside it.
