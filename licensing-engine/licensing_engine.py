"""
EnterpriseLicensingEngine — VPC-native, zero-telemetry commercial meter.

This is a peer service to the data plane (gateway / IntentCore), running inside
the customer's own network. It measures the two commercial units the IntentGate
platform sells and produces a cryptographically signed, aggregate-only usage
statement for true-up. It never receives, stores, or transmits prompts,
payloads, policies, audit events, or transaction values.

# The two meters

  IntentGrant  -> Governed Agents. Distinct AUTONOMOUS identities placed under
                 active business-authority governance (owner, active grant,
                 approval path, or attestation). Human owners and approvers are
                 NOT counted — governing human authority carries no per-seat
                 charge, by design.
  IntentGate   -> Monthly Active Protected Agents (MAPA). A distinct STABLE
                 workload identity (SPIFFE ID, service account, ...) with at
                 least one enforced runtime authorization decision in the
                 reporting period. Presence, not volume.

# Three guarantees (mirrored by test_licensing_engine.py)

  1. De-duplication. Both meters are Python sets keyed by stable identity.
     A workload that executes 5,000,000 times is a single set membership, so
     it counts as exactly one MAPA. Ephemeral pod restarts that reuse the same
     stable identity never inflate the count.

  2. Privacy by design. `build_usage_statement()` constructs a dict whose only
     value-bearing fields are aggregate integer counters. There is no field in
     which a prompt, payload, policy, or transaction value could be placed, so
     the engine is physically incapable of leaking runtime content — it never
     receives it in the first place.

  3. Soft enforcement, never fail-open. `record_active_protected_agent()` is a
     bookkeeping call that returns None and never raises for commercial
     reasons. It is fully decoupled from the security decision. If this engine
     is down, over quota, or absent, the gateway's authorization path is
     unaffected. `security_permitted()` shows the contract: the licensing state
     is never an input to whether an agent is allowed to act. Overage is
     recorded locally and reconciled as a commercial true-up.

# Signing

Ed25519, the same primitive the platform already uses for license keys and
grant bundles. The private key is provisioned at install and lives only inside
the customer deployment; the matching public key is registered with the vendor
at contract time so a statement can be verified at true-up without the vendor
ever seeing runtime data. Rotating the key is a contract-time operation.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# The only value-bearing keys the engine will ever emit. Enforced at build time
# so a future edit cannot accidentally add a runtime-content field.
_ALLOWED_STATEMENT_KEYS = frozenset(
    {
        "statement_type",
        "issuer",
        "customer_id",
        "period",
        "intentgrant",
        "intentgate",
        "not_metered",
        "not_reported",
        "commitment",
        "status",
    }
)

_NOT_METERED = ["authorization_calls", "tokens", "bandwidth"]
_NOT_REPORTED = ["prompts", "payloads", "policies", "audit_events", "transaction_values"]


def _period_key(when: Optional[datetime] = None) -> str:
    """Reporting period bucket, e.g. '2026-07'. UTC, month-granular."""
    when = when or datetime.now(timezone.utc)
    return f"{when.year:04d}-{when.month:02d}"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _canonical(obj: dict) -> bytes:
    """Deterministic bytes for signing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class Commitment:
    """Contracted annual commitment. Soft — never used to block enforcement."""

    governed_agent_quota: int = 0
    mapa_quota: int = 0


@dataclass
class _PeriodMeters:
    """The two sets for one reporting period. Sets give O(1) de-dup."""

    governed_agents: set[str] = field(default_factory=set)
    active_protected_agents: set[str] = field(default_factory=set)
    # Humans are tracked only so the statement can say how many are INCLUDED.
    # They are never part of a billable count.
    human_participants: set[str] = field(default_factory=set)


class EnterpriseLicensingEngine:
    """
    Local commercial meter. Thread-safe. Optionally persists period sets to a
    JSON file so a restart within a period neither loses nor re-inflates counts.
    """

    def __init__(
        self,
        customer_id: str,
        signing_key: Ed25519PrivateKey,
        commitment: Optional[Commitment] = None,
        state_path: Optional[str] = None,
        issuer: str = "intentgate",
    ) -> None:
        self._customer_id = customer_id
        self._key = signing_key
        self._commitment = commitment or Commitment()
        self._state_path = state_path
        self._issuer = issuer
        self._lock = threading.Lock()
        self._periods: dict[str, _PeriodMeters] = {}
        if state_path and os.path.exists(state_path):
            self._load()

    # ---- meter A: IntentGrant governed agents -----------------------------

    def register_governed_agent(self, agent_id: str, when: Optional[datetime] = None) -> None:
        """
        Place an autonomous identity under governance for the period. Idempotent:
        registering the same agent again is a no-op set membership.
        """
        with self._lock:
            self._bucket(when).governed_agents.add(agent_id)
            self._persist()

    def record_human_participant(self, subject_id: str, when: Optional[datetime] = None) -> None:
        """
        Note a human owner/approver/delegator. Tracked ONLY to report the count
        as INCLUDED. This never affects a billable meter.
        """
        with self._lock:
            self._bucket(when).human_participants.add(subject_id)
            self._persist()

    # ---- meter B: IntentGate MAPA -----------------------------------------

    def record_active_protected_agent(
        self, stable_identity: str, when: Optional[datetime] = None
    ) -> None:
        """
        Called by the data plane when an enforced runtime decision occurs for a
        stable workload identity. Bookkeeping only: returns None, never raises
        for commercial reasons, and is entirely decoupled from the security
        decision. Volume is irrelevant — the set collapses N calls to one MAPA.
        """
        try:
            with self._lock:
                self._bucket(when).active_protected_agents.add(stable_identity)
                self._persist()
        except Exception:
            # A licensing bookkeeping failure must never propagate into the
            # enforcement path. Swallow, keep protecting.
            return None

    # ---- the soft-enforcement contract ------------------------------------

    @staticmethod
    def security_permitted(policy_decision: bool) -> bool:
        """
        The security decision is a pure function of policy — never of licensing
        state. This method exists to make that contract explicit and testable:
        the engine has no way to turn `policy_decision` into a denial. Overage
        is a commercial true-up, not a fail-open condition.
        """
        return policy_decision

    # ---- counters / overage (informational, never blocking) ---------------

    def governed_agent_count(self, when: Optional[datetime] = None) -> int:
        with self._lock:
            return len(self._bucket(when).governed_agents)

    def mapa_count(self, when: Optional[datetime] = None) -> int:
        with self._lock:
            return len(self._bucket(when).active_protected_agents)

    def human_participant_count(self, when: Optional[datetime] = None) -> int:
        with self._lock:
            return len(self._bucket(when).human_participants)

    def overage(self, when: Optional[datetime] = None) -> dict:
        with self._lock:
            b = self._bucket(when)
            return {
                "governed_agents": max(0, len(b.governed_agents) - self._commitment.governed_agent_quota),
                "mapa": max(0, len(b.active_protected_agents) - self._commitment.mapa_quota),
            }

    # ---- signed usage statement -------------------------------------------

    def build_usage_statement(self, when: Optional[datetime] = None) -> dict:
        """
        Assemble the aggregate-only statement body. By construction it contains
        nothing but integer counters and status strings; see the key allow-list
        assertion below.
        """
        with self._lock:
            b = self._bucket(when)
            gov, mapa = len(b.governed_agents), len(b.active_protected_agents)
            over = {
                "governed_agents": max(0, gov - self._commitment.governed_agent_quota),
                "mapa": max(0, mapa - self._commitment.mapa_quota),
            }

        within = over["governed_agents"] == 0 and over["mapa"] == 0
        body = {
            "statement_type": "LICENCE_USAGE_STATEMENT",
            "issuer": self._issuer,
            "customer_id": self._customer_id,
            "period": _period_key(when),
            "intentgrant": {
                "governed_agents": gov,
                "human_owners_and_approvers": "INCLUDED",
            },
            "intentgate": {
                "monthly_active_protected_agents": mapa,
            },
            "not_metered": list(_NOT_METERED),
            "not_reported": list(_NOT_REPORTED),
            "commitment": {
                "governed_agent_quota": self._commitment.governed_agent_quota,
                "mapa_quota": self._commitment.mapa_quota,
                "overage": over,
            },
            "status": "WITHIN_COMMITMENT" if within else "OVER_COMMITMENT_TRUE_UP",
        }

        # Guarantee 2, enforced: no field outside the allow-list can exist, so a
        # prompt/payload/policy value has nowhere to live.
        leaked = set(body) - _ALLOWED_STATEMENT_KEYS
        assert not leaked, f"statement would leak non-aggregate fields: {leaked}"
        return body

    def sign_usage_statement(self, when: Optional[datetime] = None) -> dict:
        """
        Return the statement plus a detached Ed25519 signature over its
        canonical form, and the public key so the vendor can verify at true-up.
        """
        body = self.build_usage_statement(when)
        canonical = _canonical(body)
        signature = self._key.sign(canonical)
        pub = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return {
            "statement": body,
            "algorithm": "Ed25519",
            "signature": _b64u(signature),
            "public_key": _b64u(pub),
        }

    @staticmethod
    def verify_usage_statement(signed: dict) -> bool:
        """
        Verify a signed statement with the embedded public key. (At true-up the
        vendor verifies against the public key registered at contract time, not
        a self-embedded one; this helper is for local round-trip checks.)
        """
        try:
            pub_raw = base64.urlsafe_b64decode(_pad(signed["public_key"]))
            sig = base64.urlsafe_b64decode(_pad(signed["signature"]))
            Ed25519PublicKey.from_public_bytes(pub_raw).verify(
                sig, _canonical(signed["statement"])
            )
            return True
        except (KeyError, InvalidSignature, ValueError):
            return False

    # ---- persistence ------------------------------------------------------

    def _bucket(self, when: Optional[datetime]) -> _PeriodMeters:
        return self._periods.setdefault(_period_key(when), _PeriodMeters())

    def _persist(self) -> None:
        if not self._state_path:
            return
        snapshot = {
            p: {
                "governed_agents": sorted(m.governed_agents),
                "active_protected_agents": sorted(m.active_protected_agents),
                "human_participants": sorted(m.human_participants),
            }
            for p, m in self._periods.items()
        }
        tmp = f"{self._state_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh)
        os.replace(tmp, self._state_path)

    def _load(self) -> None:
        with open(self._state_path, encoding="utf-8") as fh:
            snapshot = json.load(fh)
        for p, m in snapshot.items():
            self._periods[p] = _PeriodMeters(
                governed_agents=set(m.get("governed_agents", [])),
                active_protected_agents=set(m.get("active_protected_agents", [])),
                human_participants=set(m.get("human_participants", [])),
            )


def _pad(s: str) -> str:
    return s + "=" * ((4 - len(s) % 4) % 4)


# ---- key helpers ----------------------------------------------------------

def load_signing_key(pem_path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key PEM provisioned at install."""
    with open(pem_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{pem_path} is not an Ed25519 private key")
    return key


def generate_signing_key() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 key (tests / first-run install)."""
    return Ed25519PrivateKey.generate()
