# IntentGate KQL pack for Microsoft Sentinel

KQL queries for the IntentGate audit table `IntentGate_CL`. Drop any
file's contents into Sentinel's Logs blade.

Assumes the gateway is configured to forward audit to your Log
Analytics workspace via the Logs Ingestion API (`INTENTGATE_SIEM_SENTINEL_*`
env vars on the gateway pod) and the custom table is named
`IntentGate_CL`.

## Files

| File | What it answers |
|---|---|
| `denied-calls-last-hour.kql` | Every block decision in the last hour |
| `policy-failures-by-rule.kql` | Which Rego rules are firing most |
| `top-agents-escalating.kql` | Agents triggering human-review escalations |
| `budget-exceeded-timechart.kql` | Hour-bucketed budget denials |
| `jit-elevations.kql` | Recent privileged elevations and who approved them |
| `latency-p95-per-tool.kql` | Authorization latency by tool |
| `revoked-token-reuse.kql` | Attempts to use revoked capability tokens |
| `decisions-per-minute.kql` | Live decision-rate chart for the on-call dashboard |

## Field naming

KQL appends `_s` to string columns, `_d` to numeric columns, `_b` to
boolean columns. The queries assume the standard mapping the gateway
ships; if your DCR transform renames fields you'll need to adjust.
