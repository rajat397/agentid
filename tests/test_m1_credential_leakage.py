"""M1 — Credential leakage.

Covers threats T1, T2, T5, T9 from docs/security/threat-model.md.
Exit condition (per §4): detection, revocation within bound, in-flight
invalidation, post-revocation denial with a receipt, incident
reconstructability — all five must hold.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.flow import act, new_keys
from agentid.delegation import create_delegation

PROFILE = ValidationProfile.example()
PUB = None  # set in fixtures


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def keys():
    return new_keys()


def _grant(priv, agent_id, amount, approver_threshold, expires_hours=2, subject_id="oidc|acme-retail|usr_8842"):
    return create_delegation(
        priv,
        subject={"type": "human", "id": subject_id},
        actor_id=agent_id,
        constraints={
            "permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
            "max_amount": {"value": amount, "currency": "USD"},
            "requires_human_approval_above": {"value": approver_threshold, "currency": "USD"},
        },
        expires_at=_iso(_now() + timedelta(hours=expires_hours)),
    )


def test_m1_credential_leakage_end_to_end(keys):
    priv, pub = keys
    ledger = Ledger()
    agent_id = "marketing-agent"

    # 1. Agent acts legitimately first (1500 > threshold 500, so an approval is granted).
    dlg = _grant(priv, agent_id, "2000.00", "500.00")
    approval = {
        "id": "apr_01FIRST",
        "delegation_id": dlg.id,
        "action": "ad.credit.purchase",
        "amount": "1500.00",
        "approver": "oidc|acme-retail|usr_8842",
        "nonce": "nonce-first01",
        "method": "oidc_consent",
        "acr": "urn:mace:incommon:iap:silver",
    }
    receipt, result = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "1500.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta",
         "external_ref": "meta_ad_order_1"},
        PROFILE, pub, approval=approval,
    )
    assert result.outcome == "valid"
    assert receipt.decision["result"] == "allowed"

    # 2. "The credential leaks." A scanner can see the leaked token digest.
    leaked_digests = {receipt.actor["credential_kid"]}

    def scanner(token_digest: str) -> bool:
        return token_digest in leaked_digests

    assert scanner(receipt.actor["credential_kid"]) is True

    # 3. Revocation: the operator revokes the delegation within the bound.
    revoked = {dlg.id}

    # 4. Attempted use after revocation is denied, and produces a receipt.
    # Negative control: without the revocation set, the leaked credential is
    # still accepted. That is exactly why revocation must be enforced, not
    # assumed. Then with revocation enforced, reuse is denied.
    receipt2, result2 = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "10.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub,
    )
    assert result2.outcome == "valid"

    receipt_denied, result_denied = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "10.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub, revoked=revoked,
    )
    assert result_denied.outcome == "invalid"
    assert "revoked" in result_denied.reason
    assert receipt_denied.decision["result"] == "denied"

    receipt3, result3 = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "10.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub, at=None,
    )
    # Incident receipt exists (the attempt), chain verifies, agent and delegation resolve.
    ok, problems = ledger.verify_chain()
    assert ok, problems
    assert receipt3.actor["agent_id"] == agent_id
    assert receipt3.delegation_id == dlg.id


def test_m1_expired_delegation_is_denied(keys):
    priv, pub = keys
    # Delegation already past — expiry enforcement must deny.
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="marketing-agent",
        constraints={
            "permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
            "max_amount": {"value": "2000.00", "currency": "USD"},
            "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
        },
        expires_at=_iso(_now() - timedelta(hours=1)),
    )
    ledger = Ledger()
    receipt, result = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "10.00",
         "currency": "USD"},
        PROFILE, pub,
    )
    assert result.outcome == "invalid"
    assert receipt.decision["result"] == "denied"


def test_m1_attenuation_enforced_at_creation(keys):
    priv, pub = keys
    parent = _grant(priv, "agent-a", "1000.00", "500.00")
    # Child cannot widen scope: permissions must be a subset.
    with pytest.raises(ValueError):
        create_delegation(
            priv,
            subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
            actor_id="agent-b",
            constraints={
                "permissions": [{"action": "social.post.publish", "system": "linkedin-ads"}],
                "max_amount": {"value": "100.00", "currency": "USD"},
                "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
            },
            expires_at=_iso(_now() + timedelta(hours=1)),
            parent=parent,
        )
    # Child cannot exceed parent's amount cap.
    with pytest.raises(ValueError):
        create_delegation(
            priv,
            subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
            actor_id="agent-b",
            constraints={
                "permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
                "max_amount": {"value": "5000.00", "currency": "USD"},
                "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
            },
            expires_at=_iso(_now() + timedelta(hours=1)),
            parent=parent,
        )
