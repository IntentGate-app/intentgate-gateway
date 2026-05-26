# Per-tenant scope enforcement (LLM08)

The tenant-scope layer closes OWASP LLM08 (Vector & Embedding
Weaknesses) at the gateway: tool calls that hit a shared vector store
or RAG backend can no longer slip a wildcard or wrong-tenant filter
through the gateway and pull another tenant's data into the agent's
context.

## What threat does this close?

An agent running under tenant A's capability token submits a query
like:

```json
{
  "tool": "vector_search",
  "args": {
    "q": "all customer phone numbers",
    "filter": { "tenant_id": "*" },
    "limit": 50
  }
}
```

The vector store happily returns matches from every tenant — A's,
B's, C's. The agent now has cross-tenant data in its context. From
there, the LLM02 disclosure pattern handles the rest: it ends up in
a response, a follow-up tool call, or both.

The capability-token layer already allowlists which tools an agent
can call. It does NOT constrain the arguments those tools receive.
Tenant-scope enforcement is the layer that closes that gap.

## Where it sits in the pipeline

The check runs on the **request path**, after the request-side PII
filter, before the upstream forward:

```
... → policy → budget → PII filter (request side) → tenant scope → upstream
```

Three rules:

1. The tenant filter argument MUST be present on the call (or the
   gateway will auto-inject it from the capability token, depending
   on the action).
2. The tenant filter value MUST equal the capability token's tenant
   claim. Mismatches are blocked.
3. The tenant filter MUST NOT be a wildcard — blank, `*`, `"all"`,
   `"any"`, null, or boolean. Wildcards are always violations even
   when the token's own tenant is empty (the superadmin case still
   requires explicit scope).

## Configuration

The operator declares which tools require tenant scoping and where
the tenant filter lives on each one. The format is a CSV:

```
INTENTGATE_TENANT_SCOPED_TOOLS=vector_search,rag_query:filter.tenant_id,embed:metadata.tenant_id
```

Each entry is `tool_name[:arg_path]`. The path is dot-separated, with
nested objects supported (`filter.tenant_id` reaches
`args["filter"]["tenant_id"]`). When the path is omitted, it
defaults to `tenant_id`.

`INTENTGATE_TENANT_SCOPE_DEFAULT_ACTION` controls the response on a
violation:

| action | what it does |
|---|---|
| `block` | refuse the call (default), return `-32017` |
| `inject` | auto-fill a missing filter from the token's tenant; mismatch / wildcard still blocks |
| `allow` | log the violation but let the call through (telemetry mode for a rollout) |

Per-tool action overrides will land in a future config-file mode;
today the action is per-gateway.

## What the audit chain stores

Counts only, never matched values:

- `check = tenant_scope`
- `decision = block` (on violation) or `decision = allow` (on inject)
- `reason` carries `tenant scope {kind} on tool "{name}"` where
  `kind ∈ {missing, wildcard, mismatch}`
- The matched **value** never leaves the gateway

## Bootstrap

`cmd/gateway/main.go` reads two env vars:

- `INTENTGATE_TENANT_SCOPED_TOOLS` — CSV described above. Empty
  disables the check.
- `INTENTGATE_TENANT_SCOPE_DEFAULT_ACTION` — `block` (default) \|
  `inject` \| `allow`.

Parse errors fail-CLOSED at startup.

## How the check is wired

The handler holds a `*tenantscope.Enforcer`. On every tool call (after
the request-side PII filter, before the upstream forward) the handler
calls `IsScoped(toolName)`. If the tool is scoped, `Check(toolName,
tokenTenant, args)` runs and returns a Decision describing what to do.

```go
if h.cfg.TenantScope != nil && h.cfg.TenantScope.IsScoped(params.Name) {
    var tokenTenant string
    if capResult.token != nil {
        tokenTenant = capResult.token.Tenant
    }
    tsDec := h.cfg.TenantScope.Check(params.Name, tokenTenant, params.Arguments)
    if tsDec.Violation != "" && !tsDec.Allowed() {
        // -32017
    }
    if tsDec.Mutated {
        // tenant filter was injected — audit + continue
    }
}
```

The full source is in `internal/tenantscope/`. The realistic test
(`TestEnforcer_CrossTenantQueryBlocked`) exercises the exact attack:
a tenant-a agent attempting to query tenant-b's embeddings. The
result is the breaker open at -32017 before the vector store ever
sees the request.

## Why the superadmin case still requires a tenant-bound token

When the capability token has no tenant claim (the superadmin case),
the gateway refuses to validate an explicit filter against "no claim
on file" — that would let a leaked superadmin token call any tenant's
vector tool by simply declaring the target tenant in the args. The
correct mint path is a token attenuated to a specific tenant
(`capability mint --tenant=acme`); the gateway then enforces the
filter equality against that bound tenant.
