# PII + Credential Filter (LLM02 Defense, Bidirectional)

**Status:** Bidirectional + credential pack shipped 2026-05-26 · Opt-in via `INTENTGATE_PII_FILTER_ENABLED=true`
**Pipeline position:** Check 6, runs in **both directions** — outbound on `tools/call` arguments and inbound on `tools/call` responses
**Audience:** Engineers extending or maintaining the gateway / Rego authors

This doc explains the *implementation* of the bidirectional PII +
credential filter. For the strategic design rationale, see
`memos/llm02-pii-filter-design.md` (PII output-side, original ship)
and `memos/response-inspection-pipeline-design.md` (the bidirectional
+ credential extension that landed later the same day). For
customer-facing claims, see Section 1 of
`docs/IntentGate-Vendor-Security-Pack.docx`.

---

## The threats closed

**OWASP LLM Top 10 LLM02 — Sensitive Information Disclosure.** Two
distinct breach patterns the gateway now closes symmetrically:

- *Response side.* An upstream MCP tool returns a result that contains
  PII the agent shouldn't see — a customer record dump that includes
  emails and IBANs when the user only asked for an order status, a
  support ticket transcript that leaks a third party's phone number,
  a log search that surfaces credit cards stored by mistake.
- *Request side.* An agent that already holds PII in its context (from
  memory, from a previous tool call, from the user prompt) includes
  that PII in arguments going *outbound* — e.g. putting a customer's
  email into a `web_search` query, or an IBAN into a third-party CRM
  call. Capability + policy gate *which* tool is called; the
  request-side filter scrubs the *contents* of allowed calls.

**Credential leakage (LLM02 extension).** The same engine catches
authentication secrets in either direction: AWS access + secret keys,
GitHub PATs, JWTs, OAuth bearer tokens, SSH private keys, GCP
service-account JSON, plus a generic API-key heuristic. The default
action for the most damaging classes (`aws_secret_key`,
`ssh_private_key`, `gcp_service_account_key`) is `block`; the rest
redact.

The first five checks (capability, intent, provenance, policy, budget)
all evaluate the request *shape* — token validity, intent match,
policy allow, budget remaining. They don't read argument values or
response bodies. Check 6 is the only check that inspects *content*,
and it does so in both directions. It is the gateway's enforcement
point for GDPR Article 5(1)(c) (minimisation), Article 32 (security
of processing), and outbound credential exfiltration prevention.

---

## Runtime architecture

One package (`internal/pii`), four call sites, no new runtime
component:

1. **Startup** — if `INTENTGATE_PII_FILTER_ENABLED=true`, the binary
   constructs a static `pii.Filter` from environment configuration
   (enabled classes, default action, per-pattern overrides, custom
   patterns) and wires it into `MCPHandlerConfig.PIIFilter`. The same
   Filter is used for both directions; classes can be PII or
   credential or any mix.
2. **Per request — Rego** — the policy stage can return a
   `pii_filter` block in its decision. The handler converts that into
   a one-shot `pii.Filter` for this request only and uses it instead
   of the static filter. Three-tier fallback: per-request override →
   static gateway filter → no filter (filter disabled).
3. **Per request — outbound (request-side)** — after the budget check
   passes and before forwarding to upstream, the handler invokes
   `filter.ApplyToMCPRequest(params.Arguments)`. The filter walks
   every string in the arguments tree recursively (maps, slices,
   nested objects), decides one of four actions, and either forwards
   the (possibly redacted-in-place) arguments or short-circuits with
   `-32015` (`CodePIIBlocked`) before the upstream sees the call.
4. **Per response — inbound (response-side)** — after the upstream
   MCP server replies to `tools/call`, `forwardToUpstream` invokes
   `filter.ApplyToMCPResult(parsed.Result)`. The filter walks every
   `content[]` text block, decides one of four actions, and either
   forwards the (possibly redacted) result or short-circuits with the
   same `-32015` code before the agent receives bytes.

Audit rows for the two directions carry the same `check: "pii"`
field; the `direction: "request" | "response"` field on the row
distinguishes them. Each direction can fire independently, and a
single tools/call can trigger both — the audit chain will show two
rows in that case.

The runtime topology is otherwise identical to a non-PII-filter
deployment — one binary, one capability-token trust boundary, one
audit chain. Headline framing: with Check 6 wired bidirectionally,
the gateway shifted from a *one-way authorisation proxy* to a
*bidirectional inspection proxy*.

---

## Detection layer

Nine built-in pattern classes ship in the binary:

| Class            | Detector                                                                                  | Why this class                                 |
| ---------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `email`          | RFC-shaped local-part `@` domain                                                          | Most common PII in tool output                 |
| `phone_intl`     | E.164-shaped sequences                                                                    | High value, low false-positive rate            |
| `iban`           | Country prefix + checked digits via mod-97                                                | Direct payment-fraud channel                   |
| `bsn`            | Dutch BSN: 9 digits + mod-11 elf-proef                                                    | Mandatory GDPR-sensitive ID in NL              |
| `credit_card`    | 13–19-digit sequences passing Luhn                                                        | PCI scope, common in support transcripts      |
| `ssn_us`         | `\d{3}-\d{2}-\d{4}` + SSA prefix rules (no 000/666/9xx, no 00 group, no 0000 serial)      | US customer support / HR tool exposure         |
| `vat_eu`         | EU country prefix + national VAT format                                                   | B2B leak via CRM tool calls                    |
| `ipv4`           | Dotted-quad with valid octets                                                             | Network-tool leak; useful for "who looked us up" attacks |
| `ipv6`           | RFC 4291 colon-hex with optional `::` compression                                         | Same as ipv4, growing share                    |

Two implementation details worth knowing:

- **Validators after regex.** IBAN / BSN / credit card / SSN all run a
  numeric validator after the regex hit. Regex narrows the candidate
  set cheaply; the validator decides whether the hit is real. This
  cuts false positives by roughly a factor of 30 on tool transcripts
  where 16-digit order numbers are common.
- **RE2, not PCRE.** Go's regexp engine is RE2, which has no negative
  lookahead. The SSN regex is therefore plain `\b\d{3}-\d{2}-\d{4}\b`
  and the prefix rules live in `validSSN` (Go code), not the regex.
  Don't try to re-introduce `(?!...)` — it won't compile.

### Custom patterns

Customer-declared additional classes come in via policy (Rego), config
file, or environment. Every custom regex passes through
`hasNestedQuantifier` — a stack-based parser that rejects any group
that contains a quantifier AND is itself followed by a quantifier
(`(a+)+`, `(a*)*`, etc.). ReDoS is the only attack vector a regex
filter exposes; this guard closes it at registration time.

---

## Actions and "most restrictive wins"

Four actions, ordered by restrictiveness:

```
Allow < Redact < Escalate < Block
```

If a response contains, say, an `email` (default action `redact`) and
an `iban` whose per-pattern override is `block`, the response is
blocked. The arithmetic is implemented in
`internal/pii/filter.go::mostRestrictive`.

- **Allow** — no detected PII, or filter disabled. Result forwarded
  unmodified.
- **Redact** — matched substrings replaced with `[REDACTED:<class>]`
  tokens. The replacement walks matches in *reverse offset order* so
  earlier substitutions don't invalidate later offsets. Result is
  re-encoded and forwarded.
- **Escalate** — same wire behaviour as Block today (return -32015),
  but the audit row carries an `escalate=true` flag for the operator
  UI to pick up. Reserved for the Pro console-driven approval flow.
- **Block** — `forwardToUpstream` returns JSON-RPC error
  `-32015 CodePIIBlocked` to the agent. The upstream response body is
  discarded; the agent sees nothing of it.

---

## Audit chain integration

The audit row uses check name `pii` (constant `audit.CheckPII`). Two
hard rules:

1. **Counts only, never values.** The row carries `counts[class] = n`
   and `matched_classes = [...]` — never the matched substrings. If
   the operator wants to see the offending bytes they look at the
   upstream's own logs, not at the gateway's tamper-evident chain.
   This is the same principle the rest of the audit chain follows for
   capability tokens (jti, not full token) and intent prompts (sha256,
   not plaintext).
2. **Action is on the row.** Allow / Redact / Block / Escalate is the
   row's `decision` field, exactly as the other five checks log it.
   That keeps the operator's verify-the-chain tooling
   (`igctl audit verify`) ignorant of which check produced any given
   row.

The row is written even when the filter chooses Allow — so an operator
can later say "show me every tools/call response that contained an
IBAN even though we let it through." Counts go to zero when no PII
matched.

---

## Configuration surface

### Environment (static, gateway-wide)

```
INTENTGATE_PII_FILTER_ENABLED=true
INTENTGATE_PII_PATTERNS=email,phone_intl,iban,bsn,credit_card
INTENTGATE_PII_DEFAULT_ACTION=redact
INTENTGATE_PII_PER_PATTERN_ACTION=iban:block,credit_card:block
```

Custom patterns from the environment use a `class=regex` shape
(comma-separated). The handler validates each one with
`hasNestedQuantifier` before adding it to the runtime filter.

### Rego (per request, overrides static)

```rego
package intentgate.policy

decision := {
    "allow":  true,
    "reason": "account holder reading own data",
    "pii_filter": {
        "enabled":        true,
        "patterns":       ["email", "phone_intl", "iban"],
        "default_action": "redact",
        "per_pattern_action": {
            "iban": "block",
        },
        "custom_patterns": [
            {"class": "order_id", "regex": `ORD-\d{6}`},
        ],
    },
}
```

When `pii_filter` is present in the Rego decision, the handler builds
a one-shot filter for this request. When it is absent, the static
gateway filter is used. When neither is configured, the response is
forwarded unmodified and the `pii` audit row records Allow with zero
counts.

Two policy-author conveniences:

- Unknown class names in `patterns` are silently skipped. Policy
  written for a future gateway that ships extra classes won't break on
  an older gateway.
- A bad action string (`"redactt"`) falls back to `redact` for the
  default and is skipped entirely for a per-pattern override. The
  policy author's intent ("be restrictive") is preserved on the rare
  case of a typo.

---

## Performance budget

The detector is hot-path code. The numbers we hold ourselves to,
measured against a 4 KB tool response on the lab gateway's reference
hardware (M2, single core, Go 1.22):

| Operation                                  | Target  | Measured |
| ------------------------------------------ | ------- | -------- |
| 9 built-in classes, no matches             | < 50 µs | 32 µs    |
| 9 built-in classes, 5 matches, redaction   | < 200 µs| 138 µs   |
| Add 10 custom patterns at startup          | < 5 ms  | 1.8 ms   |
| `hasNestedQuantifier` reject (deepest case)| < 100 µs| 11 µs    |

If a benchmark regresses past target, treat it as a correctness bug
and bisect before merging. PII filtering on a 99th-percentile tool
response should not exceed the budget for the other five checks
combined.

---

## False-positive workflow

A redacted-but-not-PII match is a customer-visible bug — the agent
sees `[REDACTED:credit_card]` where the upstream returned a 16-digit
order number. Two steps:

1. The audit row's `matched_classes` field surfaces which class fired.
   Cross-reference with the upstream's own logs (the gateway doesn't
   keep the matched bytes) to see the offending substring.
2. If the class is one we ship, the validator should have caught it
   (Luhn catches almost all spurious 16-digit numbers). File the case
   as an `internal/pii` test case before patching — the regression
   set is in `detector_test.go` and we add to it rather than tune
   regex by gut feel.

If the class is a customer custom pattern, the customer authors the
fix in their Rego.

---

## Files

```
gateway/internal/pii/
├── detector.go        — patterns, Match, Detector, validators, Redact
├── detector_test.go   — 16 tests
├── filter.go          — Action, Config, Filter, ApplyToString
├── filter_test.go     — 9 tests
├── mcp.go             — ApplyToMCPResult walks MCP content blocks
├── mcp_test.go        — 8 tests
└── from_spec.go       — converts policy.PIIFilterSpec → pii.Filter
```

The handler's call site is `gateway/internal/handlers/mcp.go` in
`forwardToUpstream`, after the upstream response is parsed and before
the metadata-injection step.

---

## What this control does *not* do

- Does not scan tool *arguments* on the request side. Argument
  sanitisation belongs in policy (Check 4) or capability scopes
  (Check 1). The PII filter is response-side by design.
- Does not catch PII that the upstream chose to encode (base64-wrapped
  CSV, gzip-compressed JSON blob). The filter operates on text blocks
  in the MCP `content[]` shape; bytes the upstream chose to hide stay
  hidden.
- Does not learn. There is no ML, no embeddings, no classifier. Every
  detection is a deterministic regex-plus-validator that an operator
  can read and audit in 30 seconds. If a class needs ML to detect, it
  isn't this filter's job.

For deployments that need any of those, the natural extension is a
sidecar (Presidio, a customer's own DLP) wired into the gateway via a
second response-stream hook — out of scope for the 2026 roadmap.
