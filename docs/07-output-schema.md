# Output schema validation (LLM05)

The output-schema layer closes OWASP LLM05 (Improper Output Handling)
at the gateway: tool responses are validated against a per-tool
JSON-Schema-subset before they reach the agent. Undeclared fields are
stripped, wrong-type scalars dropped, enum violations refused. The
agent only ever sees the shape its tool was contracted to return.

## What threat does this close?

A toolserver legitimately returns more than it was specced to return.
The spec says `read_customer` yields `{customer_id, status}`, but the
implementation handed back the whole row — including `password_hash`,
`ssn`, and any other column the database had on disk. Today the agent
has no way to know what the contract was, so the extra fields ride
right into its context and propagate.

The output-schema layer makes the contract enforceable at the gateway.

## Where it sits in the pipeline

The schema check runs on the **response path**, immediately after the
PII filter:

```
upstream forward → PII filter (response side) → output schema → inject metadata → return to agent
```

This ordering is deliberate: the PII filter may have rewritten string
content; the schema check then verifies the *post-redaction* result
still matches the declared shape. Audit rows from both stages reach
the same chain so SOC analysts can correlate.

When no schema is declared for the tool being called, the stage is a
no-op (cost: one map lookup). The gateway never refuses a call for
"missing schema" — schemas are operator opt-in.

## Configuration

Schemas live in a JSON file pointed at by
`INTENTGATE_OUTPUT_SCHEMAS_PATH`. Example:

```json
{
  "default_action": "strip",
  "tools": {
    "read_customer": {
      "schema": {
        "type": "object",
        "properties": {
          "customer_id": { "type": "string" },
          "name":        { "type": "string" },
          "status":      { "type": "string", "enum": ["active", "inactive"] }
        },
        "required": ["customer_id"],
        "additionalProperties": false
      },
      "action": "block"
    },
    "list_orders": {
      "schema": {
        "type": "object",
        "properties": {
          "orders": {
            "type": "array",
            "items": { "type": "object" }
          }
        },
        "required": ["orders"]
      }
    }
  }
}
```

`default_action` applies when a tool doesn't set its own `action`.
Per-tool `action` always wins. Three values:

| action | what it does |
|---|---|
| `allow` | log violations to the audit chain, forward unchanged |
| `strip` | remove undeclared fields and wrong-type scalars, forward the cleaned response (default) |
| `block` | refuse the response, return JSON-RPC `-32016` to the agent |

The supported schema subset:

- `type`: `object` \| `array` \| `string` \| `number` \| `integer` \| `boolean` \| `null` \| omitted (any)
- `properties`: nested per-field schemas
- `required`: required property names (object only)
- `additionalProperties`: `false` strips undeclared fields (default); `true` lets them through
- `items`: per-element schema (array only)
- `enum`: allowed scalar values

This is intentionally a strict subset of JSON Schema. The aim is
"declare what each tool returns" — not full schema-language coverage.
Tenants who need richer validation can layer a custom Rego rule on the
already-typed response.

## What the audit chain stores

Counts only, never matched values. The audit row carries:

- `check = output_schema`
- `decision = allow` (strip) or `decision = block`
- `reason` includes a per-kind counts map: `{missing_required: 1, extra_property: 3}`
- `tool` and the standard request fields

The matched **values** never leave the gateway. The point is to make
the violation auditable without re-leaking the data the schema check
just stripped.

## Bootstrap

`cmd/gateway/main.go` reads two env vars:

- `INTENTGATE_OUTPUT_SCHEMAS_PATH` — absolute path to the JSON file.
  Empty disables the check (every tool no-ops).
- `INTENTGATE_OUTPUT_SCHEMA_DEFAULT_ACTION` — `allow` \| `strip` (default) \| `block`.

Both are read at startup. Parse errors fail-CLOSED: if you point the
gateway at a malformed schema file, it refuses to boot rather than
silently leave the check off. Reload on file change is a future
enhancement; today the gateway re-reads on restart.

## How the check is wired

The handler holds an `*outputschema.Registry`. On every successful
upstream response (after the PII filter), the handler calls
`Lookup(toolName)`. If a schema is declared, `Validate(rawResult)`
runs and returns a `Result` containing per-kind counts and (when
`action=strip`) a cleaned `Stripped` JSON payload that replaces the
response body before forwarding.

```go
if h.cfg.OutputSchemas != nil && parsed.Result != nil {
    if schema, action, ok := h.cfg.OutputSchemas.Lookup(params.Name); ok {
        osRes := schema.Validate(parsed.Result)
        switch {
        case !osRes.HasViolations():
            // pass through
        case action == outputschema.ActionBlock:
            // -32016
        case action == outputschema.ActionStrip:
            parsed.Result = osRes.Stripped
        case action == outputschema.ActionAllow:
            // log only
        }
    }
}
```

The full source is in `internal/outputschema/`. Tests live next to
the implementation; the realistic end-to-end test (`TestRealistic_ResponseLeaksUndeclaredPII`)
exercises the exact threat model this layer closes: a tool that
returns the right shape *plus* email, ssn, and password_hash, and
verifies the agent only ever sees `{customer_id, name, status}`.
