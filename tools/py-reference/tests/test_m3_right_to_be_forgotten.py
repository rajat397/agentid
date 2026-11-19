"""M3 — Right to be forgotten (GDPR Art. 17).

Covers threat T8. Exit condition (per §4): receipts and delegations
enumerated, downstream systems identified, derived artifacts flagged,
deadline computed, evidence bundle exportable, no raw personal data in the
control plane's own receipts — all seven must hold.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.erasure import build_erasure_plan
from agentid.flow import act, new_keys
from agentid.delegation import create_delegation

PROFILE = ValidationProfile.example()


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def keys():
    return new_keys()


def _seed_two_fleets(priv):
    ledger = Ledger()
    dlg_a = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="marketing-agent",
        constraints={
            "permissions": [{"action": "social.post.publish", "system": "meta-ads"}],
            "max_amount": {"value": "2000.00", "currency": "USD"},
            "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    dlg_b = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_9011"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.reply", "system": "zendesk"}],
            "max_amount": {"value": "0.00", "currency": "USD"},
            "requires_human_approval_above": {"value": "0.00", "currency": "USD"},
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    for i in range(3):
        act(
            ledger, [dlg_a],
            {"action": "social.post.publish", "system": "meta-ads", "amount": "10.00",
             "currency": "USD", "resource_type": "social_account",
             "resource_id": "acme_brand", "personal_data_refs": ["cust_4471"]},
            PROFILE, _PUB, fleet="marketing",
        )
    for i in range(2):
        act(
            ledger, [dlg_b],
            {"action": "support.reply", "system": "zendesk", "amount": "0.00",
             "currency": "USD", "resource_type": "ticket",
             "resource_id": f"ticket_{1000+i}", "personal_data_refs": ["cust_4471"]},
            PROFILE, _PUB, fleet="support",
        )
    return ledger


_PUB = None  # set in fixture


@pytest.fixture(autouse=True)
def setup_pub(keys):
    global _PUB
    _PUB = keys[1]


def test_m3_full_erasure_flow(keys):
    priv, pub = keys
    ledger = _seed_two_fleets(priv)

    registry = {
        "cust_4471": [
            {"system": "meta-ads", "records": 88, "method": "customer_connector"},
            {"system": "internal_crm", "records": 31, "method": "customer_connector"},
            {"system": "zendesk", "records": 2, "method": "customer_connector"},
        ],
    }
    artifacts = [
        {"artifact": "campaign_performance_model", "owner": "growth-analytics",
         "action_required": "customer_action"},
    ]

    plan = build_erasure_plan(ledger, "cust_4471", registry, artifacts)

    assert plan.total_receipts == 5
    assert len(plan.delegations) == 2
    assert plan.days_remaining == 30
    assert plan.deadline > plan.created_at
    systems = {d["system"] for d in plan.downstream_systems}
    assert systems == {"meta-ads", "internal_crm", "zendesk"}
    assert any(a["artifact"] == "campaign_performance_model" for a in plan.derived_artifacts)

    exported = plan.to_dict()
    assert exported["total_receipts"] == 5

    # No raw personal data in the control plane's receipts — only references.
    for r in ledger.receipts:
        raw = str(r.resource) + str(r.decision) + str(r.outcome)
        for leak in ("alice@", "555-", "cust_4471@", "@example.com"):
            assert leak not in raw

    ok, problems = ledger.verify_chain()
    assert ok, problems


def test_m3_empty_subject_returns_empty_plan(keys):
    priv, pub = keys
    ledger = _seed_two_fleets(priv)
    plan = build_erasure_plan(ledger, "cust_unknown", {}, [])
    assert plan.total_receipts == 0
    assert plan.delegations == []
    assert plan.downstream_systems == []
    assert plan.days_remaining == 30
