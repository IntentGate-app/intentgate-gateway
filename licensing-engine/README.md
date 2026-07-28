# Enterprise Licensing Engine

A VPC-native, zero-telemetry commercial meter that runs as a peer service to the
data plane (gateway / IntentCore) inside the customer's own network. It measures
the two units the IntentGate platform sells and produces a cryptographically
signed, aggregate-only usage statement for true-up. It never receives, stores,
or transmits prompts, payloads, policies, audit events, or transaction values.

This is a reference implementation in Python (standard for a localized
micro-service). It is intended to be ported to the Go / Rust data plane; the
guarantees below are the contract the port must preserve.

## The two meters

| Product    | Meter | What counts |
|------------|-------|-------------|
| IntentGrant | **Governed Agents** | Distinct autonomous identities under active business-authority governance (owner, active grant, approval path, attestation). Human owners and approvers are **not** counted. |
| IntentGate | **MAPA** (Monthly Active Protected Agents) | Distinct **stable** workload identity (SPIFFE ID, service account) with at least one enforced runtime decision in the period. Presence, not volume. |

## Three guarantees (pinned by `test_licensing_engine.py`)

1. **De-duplication.** Both meters are sets keyed by stable identity. A workload
   that executes five million times is one set membership, so it is one MAPA.
   Ephemeral pod restarts that reuse the same stable identity never inflate the
   count. Tests: `test_mapa_dedup_high_volume_counts_as_one`,
   `test_ephemeral_restarts_same_identity_do_not_inflate`.

2. **Privacy by design.** `build_usage_statement()` constructs a dict whose only
   value-bearing fields are aggregate integer counters. An explicit key
   allow-list is asserted at build time, so a prompt, payload, policy, or
   transaction value has nowhere to live. The engine cannot leak runtime content
   because it never receives it. Tests:
   `test_statement_contains_no_runtime_content_fields`,
   `test_humans_excluded_from_billable_meter_but_reported_included`.

3. **Soft enforcement, never fail-open.** `record_active_protected_agent()` is a
   bookkeeping call: it returns `None`, never raises for commercial reasons, and
   is fully decoupled from the security decision. `security_permitted()` is a
   pure function of the policy decision with no licensing input, so an over-quota
   or offline meter cannot stop the gateway from protecting an agent. Overage is
   recorded locally and reconciled as a commercial true-up. Tests:
   `test_recording_never_raises_and_returns_none_over_quota`,
   `test_security_decision_independent_of_licensing`,
   `test_status_flips_to_true_up_but_never_blocks`.

## Signing

Ed25519, the same primitive already used for license keys (`console-pro/lib/license.ts`)
and grant bundles. The private key is provisioned at install and lives only inside
the customer deployment. The matching public key is registered with the vendor at
contract time, so `sign_usage_statement()` output can be verified at true-up
without the vendor seeing any runtime data. Round-trip and tamper-detection are
covered by `test_signature_verifies_and_tamper_is_detected`.

Example signed statement body:

```json
{
  "statement_type": "LICENCE_USAGE_STATEMENT",
  "issuer": "netgnarus",
  "customer_id": "ACME Corp",
  "period": "2026-07",
  "intentgrant": { "governed_agents": 3184, "human_owners_and_approvers": "INCLUDED" },
  "intentgate": { "monthly_active_protected_agents": 742 },
  "not_metered": ["authorization_calls", "tokens", "bandwidth"],
  "not_reported": ["prompts", "payloads", "policies", "audit_events", "transaction_values"],
  "commitment": { "governed_agent_quota": 3000, "mapa_quota": 800, "overage": { "governed_agents": 184, "mapa": 0 } },
  "status": "OVER_COMMITMENT_TRUE_UP"
}
```

## Restart-safe persistence

Pass `state_path` to persist period sets to a JSON file (atomic write via
temp + `os.replace`). A restart within a period reloads the sets, so counts are
neither lost nor re-inflated. Test:
`test_persistence_survives_restart_without_double_counting`.

## Usage

```python
from licensing_engine import EnterpriseLicensingEngine, Commitment, load_signing_key

eng = EnterpriseLicensingEngine(
    customer_id="ACME Corp",
    signing_key=load_signing_key("/etc/intentgate/licence-signer.pem"),
    commitment=Commitment(governed_agent_quota=3000, mapa_quota=800),
    state_path="/var/lib/intentgate/meter.json",
)

# IntentGrant control plane, when an agent is placed under governance:
eng.register_governed_agent("agent://acme/orders-bot")
eng.record_human_participant("alice@acme.com")   # included, never billed

# IntentGate data plane, on each enforced decision (bookkeeping only):
eng.record_active_protected_agent("spiffe://acme/payments")

# At the reporting interval:
signed = eng.sign_usage_statement()
assert EnterpriseLicensingEngine.verify_usage_statement(signed)
```

## Porting to Go / Rust

- **Sets → `map[string]struct{}` (Go) / `HashSet<String>` (Rust)**, one pair per
  reporting period, guarded by a mutex.
- **Canonical signing** must match byte-for-byte: JSON with sorted keys and no
  whitespace (`separators=(",", ":")` here), then `ed25519.Sign`. Keep the same
  field order/allow-list so signatures verify across the reference and the port.
- **The soft-enforcement boundary is the important invariant**: the record call
  must sit off the enforcement path (fire-and-forget, error-swallowing). Do not
  let a metering error return up into the authorization decision.
- **Keep the allow-list check.** Reproduce the `_ALLOWED_STATEMENT_KEYS`
  assertion so a future field addition can't turn the statement into a data
  channel.

## Run the tests

```bash
cd licensing-engine
python -m pytest -q
```

## Dependencies

`cryptography` (Ed25519). Standard library otherwise.
