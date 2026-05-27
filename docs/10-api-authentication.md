# API authentication

This document describes how callers authenticate against the IntentGate
API. Quickstart Guide 01 covers the operational steps; this one covers
the authentication model, the threat surface, and the standard
follow-up questions.

## Three API surfaces

IntentGate exposes three distinct APIs. Each has its own auth.

| Surface | Path | Caller | Auth |
|---|---|---|---|
| Tool-call | `POST /v1/mcp` | The agent | **Capability token** (HMAC Bearer) |
| Admin | `/v1/admin/*` | Operators, the Pro console | **Admin token** (shared Bearer) or OIDC session |
| SCIM 2.0 | `/scim/v2/*` | The customer's IdP | **SCIM Bearer token** per integration |

## 1. Tool-call API — capability tokens

This is the hot path: every agent call lands here, and the gateway's
four-check pipeline runs against the token on every request.

**Wire format.** A capability token is a base64url-encoded JSON
envelope with an HMAC-SHA256 signature appended. Decoded:

```json
{
  "v": 3,
  "jti": "ahX9s2f_QN07A0MBhYGn7Q",
  "root_jti": "ahX9s2f_QN07A0MBhYGn7Q",
  "iss": "intentgate",
  "tenant": "acme",
  "sub": "support-agent",
  "iat": 1779826099,
  "cav": [
    {"t": "agent_lock", "agent": "support-agent"},
    {"t": "exp", "exp": 1779829699},
    {"t": "tool_allow", "tools": ["read_customer", "vector_search"]},
    {"t": "max_calls", "max_calls": 100}
  ],
  "sig": "V3DAlxLH87XNDK4us-8dc1GCDZ_cNcSOUKwM009jfsQ"
}
```

Sent on every tool call:

```
Authorization: Bearer eyJ2IjozLCJqdGki...
```

**Verification, every request.** The gateway recomputes the HMAC
chain under its master key and rejects anything that doesn't match.
Verification is in-process — no network calls, single-digit
microseconds. Caveats are then evaluated against the request: tool
in the allow-list, not expired, not over max_calls, etc. A token
that fails any caveat is refused with JSON-RPC `-32010`
(`CodeCapabilityFailed`).

**Macaroon-style attenuation.** A token holder can derive a strictly
more-restrictive child token by appending a caveat and HMAC'ing it
under the parent's signature as the new key. The chained-HMAC
construction (from Birgisson et al., 2014) guarantees that an
attenuated token can only narrow, never widen, the parent's scope —
removing a caveat breaks the signature. Attenuation requires no
access to the master key, so a service can hand out scope-reduced
tokens without ever holding the gateway's secret.

**Stateless verification.** The token is the entire authorization
state for one request. The gateway holds no per-token session.
Per-token *counters* (call counts for max_calls, taint flags) live
in the budget store (Redis or in-memory); revocation lives in the
revocation store (Postgres or in-memory).

**Threat model.**

- *Master key never leaves the gateway.* The gateway is the only
  process that can mint or verify. Tokens are signed, not encrypted —
  anyone holding the bytes can read the caveats. Treat them like
  bearer credentials: TLS only, no logging.
- *Forged signatures are rejected.* Lab card AGENT03 demonstrates
  this live.
- *Compromised tokens are revoked by `jti`.* See §3.
- *Compromised master key* — see §6.

## 2. Admin API — admin token + OIDC

`/v1/admin/*` is the surface operators use to mint tokens, revoke
them, promote policies, export audit, configure approval queues.
Two layered auth modes:

**OSS install.** A shared admin Bearer token, read from
`INTENTGATE_ADMIN_TOKEN` at startup. One operator, one token, one
secret to rotate. Suitable for self-hosted single-team deployments.

```
Authorization: Bearer $INTENTGATE_ADMIN_TOKEN
```

**Pro install.** The operator console (a separate Next.js app)
fronts the admin API with **OIDC/SAML SSO** — humans authenticate
with their corporate identity (Okta, Entra ID, Google Workspace,
anything OIDC-compliant). The console then calls the gateway's
admin API using the admin token as a service principal, with the
operator's identity propagated in audit rows via the `decided_by`
field on approval-and-policy events.

Direct admin-API calls (for automation, CI/CD, ad-hoc minting) still
use the bearer token; the console-driven path adds SSO + RBAC on top.

## 3. SCIM 2.0 API — IdP-driven provisioning

`/scim/v2/*` is the standard SCIM endpoint set for user and group
provisioning into the Pro console's RBAC store. The customer's IdP
authenticates with a per-integration **SCIM Bearer token** issued at
integration setup time and rotatable from the console's Integrations
page.

Not on the hot path for tool calls — only used by the IdP to push
operator-user provisioning events.

## Token rotation

| Token | Rotation method | Downtime |
|---|---|---|
| Capability tokens | Mint fresh, hand to the agent, old one expires (or revoke) | None |
| Admin token | Update `INTENTGATE_ADMIN_TOKEN` env var, restart the gateway | < 5s |
| Master key | See §6 — deliberate teardown of all live tokens | Cap-token re-mint required for all agents |
| SCIM token | Generate new token in console, paste into IdP, revoke old | None |

Capability tokens are designed to be short-lived. Recommended TTL is
minutes to hours; combine with `max_calls` for further bounding. The
operational pattern is: mint a token per agent session, expire it
when the session ends. Long-lived tokens (days) are supported but
not the recommended path.

## Revocation

Per-token revocation via the admin API:

```
POST /v1/admin/revoke
Authorization: Bearer $ADMIN_TOKEN
Content-Type: application/json

{"jti": "ahX9s2f_QN07A0MBhYGn7Q", "reason": "ex-employee offboarded"}
```

The revocation store (Postgres-backed in production, in-memory for
dev) is consulted on every capability check after signature
verification. Propagation across replicas is sub-second through the
shared store. A revoked token returns `CodeCapabilityFailed` with
reason `token revoked`.

Lab card AGENT10 (Capability theft — revoked token) demonstrates
the round trip live: mint → use → revoke → re-use refused.

## Audit

Every authenticated request lands in the hash-chained audit log with:

- The verified `jti` (and the chain root `root_jti` for attenuated
  tokens, so a SOC analyst can reconstruct the delegation tree)
- `tenant`, `agent_id`, `caveat_count`
- The full `check_stage`, `decision`, `reason` for the verdict

Auth failures (bad signature, expired, revoked, caveat violation,
admin-token mismatch on `/v1/admin/*`) all land too, with distinct
`check_stage` values so dashboards can separate "auth rejected" from
"policy rejected".

The audit chain is tamper-evident: rows are HMAC-linked to the
previous row. The audit-tampering lab card (Postgres rewrite of a
historical row) demonstrates that the chain catches direct row edits.

## Why not OAuth 2.0?

The most common follow-up. Honest answer: **the agent-to-gateway path
is deliberately not OAuth.** The human-to-console path **is** OIDC,
which is OAuth 2.0 plus identity tokens.

**Where OAuth/OIDC IS used:**

- **Operator console login** (Pro). Standard OIDC against the
  customer's IdP — Okta, Entra ID, Google Workspace, Auth0, Ping,
  anything OIDC-compliant. Authorization code flow with PKCE. The
  console runs NextAuth.js with OIDC providers configured.
- **SCIM provisioning** rides on OAuth 2.0 token auth in most IdP
  integrations.

**Where OAuth is NOT used — and why:**

- **Agent-to-gateway** uses capability tokens, not OAuth access
  tokens. Four deliberate reasons:
  1. **Per-call caveats beat OAuth scopes.** A capability token can
     carry `max_calls`, `tool_allow`, `agent_lock`, `step_up_at`,
     time windows, tenant binding — all on the same token, evaluated
     per request. OAuth scopes are coarser and don't compose this
     way without custom claim conventions.
  2. **Attenuation without an authorization server round-trip.** A
     token holder can derive a strictly narrower child token by
     appending a caveat and re-HMACing under the parent's signature.
     OAuth has no equivalent — every narrowed scope requires a new
     trip to the AS.
  3. **In-process verification.** No network call to an authorization
     server on every tool call. Verification is HMAC-SHA256 against
     the master key, single-digit microseconds. OAuth introspection
     against an AS adds 10–50ms per call.
  4. **No /token endpoint to attack.** The OAuth client_credentials
     and authorization_code endpoints are a regular CVE generator.
     Capability tokens are minted only via the admin API, which is
     itself protected by the admin token (or the console's OIDC
     session). Smaller attack surface.

**How OAuth and IntentGate compose:**

If a customer has invested in an OAuth/OIDC stack and wants to drive
agent authorization from it, the integration pattern is a **mint
bridge** — a small service the customer runs that:

1. Receives the agent's OAuth access token (or OIDC ID token) from
   their existing auth flow.
2. Validates it against the customer's IdP (introspection,
   JWKS-verified signature, whichever model they already use).
3. Maps OAuth scopes / OIDC claims to IntentGate caveats (which
   tools, which tenant, max_calls, TTL).
4. Calls `/v1/admin/mint` with the resulting policy to produce a
   capability token.
5. Returns the capability token to the agent for use on `/v1/mcp`.

This is a ~100-line service that gives the customer "I keep my
OAuth IdP as the source of truth, IntentGate handles per-call
authorization downstream." We can ship a reference implementation
if a prospect needs one — it's not in the OSS today.

**Summary.** OIDC for human operator login, capability tokens for
agent authorization. The agent path is deliberately not OAuth:
capability tokens carry per-call caveats, support attenuation without
a round trip, and verify in-process — properties OAuth bearer tokens
don't provide. A customer that wants their existing OAuth IdP to
remain the source of truth for identity bridges into IntentGate via
the mint pattern described above.

## Standard follow-ups

**Q: What signing algorithm?**
HMAC-SHA256 over the canonical envelope. The chosen algorithm is
fixed (no JWT-style `alg` field in the wire format), which removes
the `alg=none` and key-confusion attack classes that bit early JWT
implementations.

**Q: Can we BYO key material?**
Yes. `INTENTGATE_MASTER_KEY` is a 32-byte key the operator supplies
at boot. It can come from any source — Vault, AWS KMS, an HSM-backed
secret manager, a sealed Kubernetes Secret. The gateway never
materialises it outside the running process.

**Q: What happens if the master key is compromised?**
Compromised master key = all existing capability tokens are
forgeable. The recovery procedure is:

1. Issue a new master key from your secret manager.
2. Bring up a fresh gateway with the new key (don't rotate in-place
   — that invalidates everything atomically and you want a planned
   teardown, not an outage).
3. Re-mint capability tokens for every active agent.
4. Cut over traffic.
5. Decommission the old gateway.

The audit chain survives the rotation (it's keyed independently from
the capability HMAC). All audit history from the old gateway remains
verifiable.

**Q: TLS termination?**
The gateway expects to sit behind TLS termination — typically a
load balancer, reverse proxy, or service mesh. The bundled `lab/`
compose runs Caddy in front; production deployments are typically
ALB → gateway, Envoy → gateway, or nginx → gateway. The gateway can
serve plain HTTP on a private network safely; what it cannot do is
serve HTTPS itself (no embedded TLS termination, deliberately).

**Q: Mutual TLS for agent-to-gateway?**
Supported at the proxy layer. The gateway doesn't terminate TLS so
it doesn't validate client certs directly, but the upstream proxy
can require mTLS and pass a verified client identity in a header
that Rego policies inspect.

**Q: Per-tenant key isolation?**
Single master key per gateway today. Per-tenant key derivation is
on the roadmap as a Pro feature for multi-tenant SaaS deployments
that need tenant-controlled cryptographic isolation.

**Q: What's logged when auth fails?**
The audit row records: timestamp, remote IP, the JSON-RPC request
method, the failure reason (bad_signature / expired / revoked /
caveat_violation), and the `jti` if one was supplied (helpful for
correlating attacks). The token bytes are never logged.

## Where to verify this yourself

- **Code:** `gateway/internal/capability/` — token.go, sign.go,
  codec.go, mint.go, check.go. Open source. The package-level
  doc comment in `token.go` is the formal threat-model spec.
- **Tests:** `gateway/internal/capability/capability_test.go` —
  signature verification, attenuation, expired-token rejection,
  malformed-token rejection.
- **Lab demos:**
  - AGENT03 — Identity Spoofing (forged signature rejection)
  - AGENT10 — Capability theft (revocation propagation)
- **Live traffic in the lab:** every successful and refused tool
  call in `/audit` shows the verified `jti`, the check stage that
  passed or failed, and the resulting decision.

That's the full surface. Anything not covered above, ask and we'll
add it here — this doc is the canonical answer customers should
get when they ask about API authentication.
