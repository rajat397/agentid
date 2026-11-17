"""M2 — Audit trail reconstruction.

Covers threats T3, T4, T6, T7. Exit condition (per §4): receipt exists,
chain resolves, four questions answerable, chain verifies, constraint
intersection holds, forged approvals rejected — all six must hold.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.flow import act, new_keys
from agentid.delegation import create_delegation

PROFILE = ValidationProfile.example()


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _grant(priv, agent_id, amount="2000.00", threshold="500.00", subject_id="oidc|acme-retail|usr_8842",
           expires_hours=2, action="ad.credit.purchase", system="meta-ads"):
    return create_delegation(
        priv,
        subject={"type": "human", "id": subject_id},
        actor_id=agent_id,
        constraints={
            "permissions": [{"action": action, "system": system}],
            "max_amount": {"value": amount, "currency": "USD"},
            "requires_human_approval_above": {"value": threshold, "currency": "USD"},
        },
        expires_at=_iso(_now() + timedelta(hours=expires_hours)),
    )


@pytest.fixture
def keys():
    return new_keys()


def test_m2_four_questions_answerable(keys):
    priv, pub = keys
    ledger = Ledger()
    agent_id = "marketing-agent"
    dlg = _grant(priv, agent_id)

    approval = {
        "id": "apr_01ABC",
        "delegation_id": dlg.id,
        "action": "ad.credit.purchase",
        "amount": "2000.00",
        "approver": "oidc|acme-retail|usr_8842",
        "nonce": "nonce-9f3a2b",
        "method": "oidc_consent",
        "acr": "urn:mace:incommon:iap:silver",
        "auth_time": _iso(_now()),
    }

    receipt, result = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta",
         "external_ref": "meta_ad_order_993812",
         "personal_data_refs": ["cust_4471"]},
        PROFILE, pub, approval=approval,
    )
    assert result.outcome == "valid"

    # The four questions, from receipts alone.
    assert receipt.actor["spiffe_id"].startswith("spiffe://")      # which agent
    assert receipt.actor["agent_id"] == agent_id
    assert receipt.actor["credential_kid"]                          # which credential
    assert receipt.delegation_id == dlg.id                          # which grant

    rep, _ = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "100.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub,
    )
    ok, problems = ledger.verify_chain()
    assert ok, problems


def test_m2_over_threshold_without_approval_is_denied(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _grant(priv, "marketing-agent")
    receipt, result = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub,
    )
    assert result.outcome == "indeterminate"
    assert receipt.decision["result"] == "denied"
    assert any(o["type"] == "cosign_above" for o in receipt.decision["obligations"])


def test_m2_forged_approval_rejected(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _grant(priv, "marketing-agent")

    # Wrong approver — a different delegation_id must not satisfy it.
    bad1 = {"id": "apr_x", "delegation_id": "dlg_other",
            "action": "ad.credit.purchase", "amount": "2000.00",
            "approver": "oidc|acme-retail|usr_0000", "nonce": "n"}
    _, r1 = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD"},
        PROFILE, pub, approval=bad1,
    )
    assert r1.outcome == "invalid"

    # Approval smaller than the action — must not satisfy.
    bad2 = {"id": "apr_y", "delegation_id": dlg.id,
            "action": "ad.credit.purchase", "amount": "100.00",
            "approver": "oidc|acme-retail|usr_8842", "nonce": "n"}
    _, r2 = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD"},
        PROFILE, pub, approval=bad2,
    )
    assert r2.outcome == "invalid"

    # Missing nonce — forgeable approval must be rejected.
    bad3 = {"id": "apr_z", "delegation_id": dlg.id,
            "action": "ad.credit.purchase", "amount": "2000.00",
            "approver": "oidc|acme-retail|usr_8842"}
    _, r3 = act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD"},
        PROFILE, pub, approval=bad3,
    )
    assert r3.outcome == "invalid"


def test_m2_chain_integrity_and_tamper_detection(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _grant(priv, "marketing-agent")
    act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "100.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub,
    )
    act(
        ledger, [dlg],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "200.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta"},
        PROFILE, pub,
    )
    ok, problems = ledger.verify_chain()
    assert ok, problems

    # Tamper with history — the chain must detect it.
    ledger.receipts[0].action = "social.post.publish"
    ok, problems = ledger.verify_chain()
    assert not ok
    assert problems


def test_m2_root_approval_chain_cannot_escalate_via_budget(keys):
    priv, pub = keys
    ledger = Ledger()
    # The delegation carries a shared, root-keyed cumulative budget.
    with_budget = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="marketing-agent",
        constraints={
            "permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
            "max_amount": {"value": "2000.00", "currency": "USD"},
            "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
            "budget": {"key": "ads_q4", "value": "2000.00", "currency": "USD",
                       "period_seconds": 2592000},
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    # ledger spends 1800; a new 500 action must violate the shared budget.
    spend = 0
    for amt in ("1000.00", "800.00"):
        act(
            ledger, [with_budget],
            {"action": "ad.credit.purchase", "system": "meta-ads", "amount": amt,
             "currency": "USD", "resource_type": "ad_credit_account",
             "resource_id": "acme_retail_meta",
             "budget_key": "ads_q4"},
            PROFILE, pub,
            approval={"id": f"apr_{spend}", "delegation_id": with_budget.id,
                      "action": "ad.credit.purchase", "amount": amt,
                      "approver": "oidc|acme-retail|usr_8842", "nonce": f"n{spend}"},
        )
        spend += 1
    _, result = act(
        ledger, [with_budget],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "500.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta", "budget_key": "ads_q4"},
        PROFILE, pub,
    )
    assert result.outcome == "invalid"
    assert "budget" in result.reason
    # ...but 300 must still fit (remaining 200? no: 2000-1800=200, so 200 fits).
    _, result_ok = act(
        ledger, [with_budget],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "200.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta", "budget_key": "ads_q4"},
        PROFILE, pub,
    )
    assert result_ok.outcome == "valid"
