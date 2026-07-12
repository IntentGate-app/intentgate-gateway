# Design spec — Action approval: manager portal login + ServiceNow round-trip

Status: draft for review
Owner: IntentGate
Applies to: gateway `internal/approvals`, console-pro Approvals, new `internal/approvals/servicenow`

---

## 1. Problem

IntentGate holds high-risk actions for a human (policy `escalate`, mandatory hold,
and reference-verification quarantine all land in the approvals queue). Today the
only way to release a held action is the console Approvals queue, reached by an
operator account. Two things are missing for a real enterprise deployment:

1. **The approver is not the engineer.** Releasing a held payment is a business
   decision (finance / AP control owner), made by someone independent of the agent
   and of whoever operates the gateway. The portal needs a real **manager-approver
   login and role**, separate from the operator.
2. **Approvers live in ServiceNow, not our console.** A finance manager will action
   a ServiceNow approval they already receive daily; they will not log into a new
   security console. Held actions must **raise a ServiceNow approval ticket** and
   accept the decision back.

This spec covers both, off a single source of truth so they never diverge.

Scope note / positioning: this is **runtime action approval** ("should this exact
payment, to this payee, right now, execute"), not IGA access approval ("should this
identity hold this entitlement"). We borrow the approval UX and routing pattern from
Omada / SailPoint / ServiceNow; we do not become an IGA. The action, not the access,
is the unit of approval.

---

## 2. Principles

- **One approval request is the source of truth.** Channels (portal, ServiceNow) are
  views/actuators over it, never independent stores.
- **First decision wins, idempotently.** Whichever channel decides first closes the
  request; the other channel is reconciled to that outcome. Late or duplicate
  callbacks are no-ops.
- **Fail-closed.** No decision within the SLA → the action is blocked, never released.
- **Separation of duties.** Approver ≠ operator ≠ the agent's owner. Enforced by role
  and, where configured, by identity (an approver cannot approve their own request).
- **Every decision is evidence.** Channel, approver identity, ServiceNow ticket id,
  decision, and timing are written to the tamper-evident audit chain.

---

## 3. The recommended flow

```
  agent → gateway → [checks] → QUARANTINE/ESCALATE
                                   │
                                   ▼
                         ApprovalRequest created           ← single source of truth
                            (state = pending)
                          ┌────────────┴─────────────┐
                          ▼                           ▼
                 Portal Approvals queue        ServiceNow approval ticket
                 (manager logs in, SSO)        (raised via API, deep link back)
                          │                           │
                          │  approve/reject           │  approve/reject (SN workflow)
                          ▼                           ▼
                          └──────────► decision ◄──────┘
                                first-wins, idempotent
                                   │
                        gateway enforces outcome
                     approve → forward   reject/timeout → block
                                   │
                          audit chain entry
                  (channel, approver, SN ticket id, reason)
```

### Synchronous vs asynchronous — the key design point

A tool call is synchronous, but a manager approval takes minutes to hours. We cannot
hold a live HTTP call open that long. So held actions run in one of two modes,
configurable per tool/policy:

- **Short hold (existing behaviour).** For approvals expected in seconds (an operator
  watching the queue), the call blocks up to `INTENTGATE_APPROVAL_TIMEOUT_S` and then
  fail-closes. This is what the lab shows today.
- **Async hold (new, required for ServiceNow).** The gateway immediately returns a
  structured **`pending_approval`** response to the agent (JSON-RPC error with a
  `pending_id` and a human-readable "held for approval" message). The action is
  parked server-side. When the decision arrives, the outcome is recorded; the agent
  resumes by **re-submitting the same call**, which the gateway now resolves against
  the stored decision (short-circuit allow, or block with the rejection reason). An
  idempotency key on the call (`pending_id`) prevents double execution.

Async is the correct model for ServiceNow. The agent framework treats `pending_approval`
like any other "come back later" signal (the same way a long-running tool would).

---

## 4. Manager-approver portal login

Required so a real manager — not the operator/engineer — can approve in the portal.

- **Authentication.** Console-pro moves from mock/basic auth to **OIDC/SAML SSO**
  (customer IdP). Already partially present via `AUTH_PROVIDER`; add an enterprise
  provider path. Approvers sign in with their corporate identity.
- **Roles.** Add an **`approver`** role distinct from `operator`/`admin`/`viewer`.
  An approver sees only the Approvals queue (and their own audit), nothing else.
  Optionally scope approvers to a **domain** (finance approvers see finance-tool
  approvals) via a request→approver-group mapping.
- **Separation of duties.** Server-side check: the approver's identity must differ
  from the agent's owner and from the operator who last touched the policy; the same
  identity cannot both raise and approve. Configurable dual-control (two distinct
  approvers) for the highest-value actions, reusing the elevation two-admin pattern
  already in the console.
- **What the approver sees.** Agent, tool, resolved action, payee/amount, the reason
  (e.g. "payee NEW-PARTY is not in the vendor master"), the evidence link, and
  Approve / Reject with a mandatory note. Optional step-up (TOTP) before approve.

This portal path is the **fallback when there is no ITSM**, and the native path for
customers who prefer it.

---

## 5. ServiceNow integration

### 5.1 Raise
On `pending`, IntentGate calls ServiceNow to create an approval artefact. Two options,
pick per customer:

- **Approval on a record** (recommended): create a record in a lightweight custom
  table `x_intentgate_action_approval` (or a Change/Request record) and attach a
  **sysapproval_approver** entry routed by the customer's assignment rules. This uses
  ServiceNow's native approval workflow, so routing, escalation, reminders, and
  mobile approve/reject all come for free.
- **Catalog request / RITM** for shops that standardise on Service Catalog.

Payload → ServiceNow fields:

| IntentGate field            | ServiceNow field                    |
|-----------------------------|-------------------------------------|
| pending_id                  | correlation_id                      |
| agent_id, tool              | short_description                   |
| resolved action + payee/amt | description                         |
| reason (why held)           | description / u_reason              |
| evidence deep link          | u_evidence_url (back to portal)     |
| tenant, severity            | assignment_group / priority         |

### 5.2 Decide + callback
The manager approves/rejects in ServiceNow. On state change, either:

- **Push (preferred):** a ServiceNow Business Rule / Flow calls
  `POST /v1/admin/approvals/{pending_id}/callback` with the decision, approver
  sys_id, and a shared secret (HMAC). Low latency.
- **Pull (fallback / no outbound):** IntentGate polls the record state on an interval
  for environments that don't allow ServiceNow → IntentGate egress.

The callback is **idempotent** and **first-wins**: if the portal already decided, the
ServiceNow ticket is closed to match and the callback is a no-op, and vice-versa.

### 5.3 Reconciliation
- Approve in portal → IntentGate closes the ServiceNow approval (approved, actor noted).
- Approve in ServiceNow → IntentGate marks the portal request decided and removes it
  from the queue.
- Timeout/SLA breach in IntentGate → cancel the ServiceNow approval (state = cancelled,
  reason = expired) and block the action.

---

## 6. Data model (extends `internal/approvals`)

`ApprovalRequest` (new/extended fields):

- `pending_id` (existing), `tenant`, `agent_id`, `tool`, `action_ir`
- `origin_check` — `refverify` | `policy_escalate` | `mandatory_hold` (fixes today's
  mislabel where refverify holds read as `policy`)
- `reason`, `evidence_url`
- `mode` — `sync` | `async`
- `state` — `pending` | `approved` | `rejected` | `expired` | `cancelled`
- `decided_by` (identity), `decided_channel` (`portal` | `servicenow`), `decided_at`,
  `decision_note`
- `servicenow_sys_id`, `servicenow_number`
- `sla_deadline`

State machine: `pending → {approved, rejected, expired}`; `approved/rejected` are
terminal; a channel that arrives after terminal is reconciled, not re-applied.

---

## 7. Audit & evidence

Every decision appends to the hash-chained audit log with: `origin_check`,
`decided_channel`, `decided_by`, `servicenow_number`, `decision`, `note`, timings.
This is the payoff for the buyer: a held payment's release is provably tied to a named
business approver and a ServiceNow ticket — segregation of duties, evidenced, and
tamper-evident end to end. Feeds the governance reports and the SIEM export.

---

## 8. Configuration (new env)

```
INTENTGATE_APPROVAL_MODE=async|sync            # per-tool override in policy
INTENTGATE_APPROVAL_SLA_S=86400                # async fail-closed deadline
INTENTGATE_SERVICENOW_ENABLED=true
INTENTGATE_SERVICENOW_INSTANCE_URL=https://acme.service-now.com
INTENTGATE_SERVICENOW_AUTH=oauth|basic
INTENTGATE_SERVICENOW_TABLE=x_intentgate_action_approval
INTENTGATE_SERVICENOW_CALLBACK_HMAC_SECRET=...
INTENTGATE_SERVICENOW_ASSIGNMENT_GROUP_MAP=finance:AP Approvers,...
```

---

## 9. Phasing

1. **Generic async approval core.** `async` hold mode, `pending_approval` agent
   response, resume-on-resubmit, `origin_check` on the request + audit (also fixes the
   refverify audit-label nit). A vendor-neutral `POST /callback` contract. Demoable in
   the lab with a curl "approve".
2. **Portal manager login.** OIDC/SAML SSO + `approver` role + SoD checks + the
   approver-only Approvals view. Works with no ITSM at all.
3. **ServiceNow connector.** Raise + callback + reconcile against the generic core.
4. **Dual control + step-up + assignment-group routing.** Hardening for high-value.

Phase 1 is the foundation both other phases sit on, and is worth building first
because it also corrects the current audit attribution.

---

## 10. Open questions

- ServiceNow artefact: custom table vs Change vs Catalog — depends on the first
  customer's ServiceNow practice. Build the connector against an interface so the
  artefact type is pluggable.
- Async resume: re-submit-the-call vs a dedicated `resume` endpoint the agent polls.
  Re-submit is simpler for MCP clients; confirm with the SDK.
- How long may an action be parked? `SLA_S` default and whether parked context (args)
  is stored encrypted at rest for the duration.
- Positioning line to hold: action approval, not access approval — keep out of IGA.
