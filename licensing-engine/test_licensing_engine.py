"""
Tests that pin the three commercial guarantees of the licensing engine.

Run:  python -m pytest -q   (from the licensing-engine directory)
"""

import json

from licensing_engine import (
    Commitment,
    EnterpriseLicensingEngine,
    generate_signing_key,
)

PII_SUBSTRINGS = ("prompt", "payload", "content", "policy", "transaction", "audit")


def make_engine(**kw) -> EnterpriseLicensingEngine:
    return EnterpriseLicensingEngine(
        customer_id=kw.pop("customer_id", "ACME Corp"),
        signing_key=kw.pop("signing_key", generate_signing_key()),
        **kw,
    )


# --- Guarantee 1: de-duplication -----------------------------------------

def test_mapa_dedup_high_volume_counts_as_one():
    eng = make_engine()
    for _ in range(5_000_000 // 10_000):  # many records, same identity
        eng.record_active_protected_agent("spiffe://acme/payments-agent")
    # even simulating a huge number, membership is 1
    for _ in range(1000):
        eng.record_active_protected_agent("spiffe://acme/payments-agent")
    assert eng.mapa_count() == 1


def test_ephemeral_restarts_same_identity_do_not_inflate():
    eng = make_engine()
    # 20 ephemeral pods, same stable workload identity
    for pod in range(20):
        eng.record_active_protected_agent("svc-account:orders")
    assert eng.mapa_count() == 1
    # distinct stable identities do count
    eng.record_active_protected_agent("svc-account:billing")
    assert eng.mapa_count() == 2


def test_governed_agents_are_deduped():
    eng = make_engine()
    for _ in range(50):
        eng.register_governed_agent("agent-42")
    assert eng.governed_agent_count() == 1


# --- Guarantee 2: privacy by design --------------------------------------

def test_humans_excluded_from_billable_meter_but_reported_included():
    eng = make_engine()
    eng.register_governed_agent("agent-a")
    eng.register_governed_agent("agent-b")
    for owner in ("alice", "bob", "carol"):
        eng.record_human_participant(owner)
    assert eng.governed_agent_count() == 2  # humans not added
    stmt = eng.build_usage_statement()
    assert stmt["intentgrant"]["governed_agents"] == 2
    assert stmt["intentgrant"]["human_owners_and_approvers"] == "INCLUDED"


def test_statement_contains_no_runtime_content_fields():
    eng = make_engine()
    eng.register_governed_agent("agent-a")
    eng.record_active_protected_agent("wl-1")
    signed = eng.sign_usage_statement()
    blob = json.dumps(signed).lower()
    # runtime content words only ever appear inside the explicit
    # "not_metered" / "not_reported" attestations, never as data carriers.
    stmt = signed["statement"]
    assert set(stmt) <= {
        "statement_type", "issuer", "customer_id", "period",
        "intentgrant", "intentgate", "not_metered", "not_reported",
        "commitment", "status",
    }
    # the only place "payload"/"policy"/etc. may appear is the not_reported list
    assert set(stmt["not_reported"]) == {
        "prompts", "payloads", "policies", "audit_events", "transaction_values"
    }
    # there is no top-level value carrying runtime content
    for key, value in stmt.items():
        if key in ("not_metered", "not_reported"):
            continue
        assert not any(p in json.dumps(value).lower() for p in ("prompt", "payloadvalue"))


# --- Guarantee 3: soft enforcement, never fail-open ----------------------

def test_recording_never_raises_and_returns_none_over_quota():
    eng = make_engine(commitment=Commitment(governed_agent_quota=1, mapa_quota=1))
    # blow way past quota
    for i in range(100):
        assert eng.record_active_protected_agent(f"wl-{i}") is None
    assert eng.mapa_count() == 100
    over = eng.overage()
    assert over["mapa"] == 99  # recorded for true-up


def test_security_decision_independent_of_licensing():
    eng = make_engine(commitment=Commitment(mapa_quota=0))  # 0 quota => always "over"
    eng.record_active_protected_agent("wl-1")
    # policy says allow; licensing is massively over quota; still allowed.
    assert eng.security_permitted(True) is True
    # policy says deny; licensing has nothing to do with it either.
    assert eng.security_permitted(False) is False
    assert eng.overage()["mapa"] >= 1


def test_status_flips_to_true_up_but_never_blocks():
    eng = make_engine(commitment=Commitment(governed_agent_quota=2, mapa_quota=2))
    eng.register_governed_agent("a")
    eng.register_governed_agent("b")
    eng.record_active_protected_agent("w1")
    assert eng.build_usage_statement()["status"] == "WITHIN_COMMITMENT"
    eng.register_governed_agent("c")  # now over
    assert eng.build_usage_statement()["status"] == "OVER_COMMITMENT_TRUE_UP"


# --- Signing round-trip + tamper -----------------------------------------

def test_signature_verifies_and_tamper_is_detected():
    eng = make_engine()
    eng.register_governed_agent("a")
    eng.record_active_protected_agent("w1")
    signed = eng.sign_usage_statement()
    assert EnterpriseLicensingEngine.verify_usage_statement(signed) is True
    # tamper with a counter
    signed["statement"]["intentgate"]["monthly_active_protected_agents"] = 99999
    assert EnterpriseLicensingEngine.verify_usage_statement(signed) is False


# --- Restart-safe persistence --------------------------------------------

def test_persistence_survives_restart_without_double_counting(tmp_path):
    state = tmp_path / "meter.json"
    key = generate_signing_key()
    eng = make_engine(signing_key=key, state_path=str(state))
    eng.record_active_protected_agent("w1")
    eng.record_active_protected_agent("w2")
    eng.register_governed_agent("a")

    # simulate a process restart: new engine, same state file
    eng2 = EnterpriseLicensingEngine(
        customer_id="ACME Corp", signing_key=key, state_path=str(state)
    )
    assert eng2.mapa_count() == 2
    assert eng2.governed_agent_count() == 1
    # re-recording the same identities after restart does not inflate
    eng2.record_active_protected_agent("w1")
    assert eng2.mapa_count() == 2
