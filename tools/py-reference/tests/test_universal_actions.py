"""Universal action model — non-monetary actions and attribute-path predicates.

Exit condition: a delegation whose constraints never mention money can
authorize a non-monetary action (support ticket), enforce aggregated counts,
region sets, minima, time windows, and envelope-bound approvals — with
attenuation holding and no core change per system.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.delegation import create_delegation
from agentid.envelope import digest as envelope_digest
from agentid.flow import act, new_keys

PROFILE = ValidationProfile.example()


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def keys():
    return new_keys()


def _support_grant(priv, **extra):
    constraints = {
        "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
        "predicates": [
            {"type": "in", "path": "/attributes/region", "values": ["eu", "us"]},
            {"type": "max", "path": "/attributes/count", "value": "50"},
            {"type": "min", "path": "/attributes/count", "value": "1"},
        ],
    }
    constraints.update(extra)
    return create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints=constraints,
        expires_at=_iso(_now() + timedelta(hours=2)),
    )


def _resolve(ledger, dlg, pub, region="eu", count="5", **kw):
    request = {
        "action": "support.ticket.resolve", "system": "zendesk",
        "resource_type": "ticket", "resource_id": "ticket_1001",
        "region": region, "count": count,
        "personal_data_refs": ["cust_4471"],
    }
    request.update(kw)
    return act(ledger, [dlg], request, PROFILE, pub)


def test_non_monetary_action_allowed_within_attribute_predicates(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _support_grant(priv)
    receipt, result = _resolve(ledger, dlg, pub)
    assert result.outcome == "valid"
    # receipt records the generic attributes; no amount required anywhere
    assert receipt.resource["attributes"]["region"] == "eu"
    assert receipt.resource["attributes"]["count"] == "5"


def test_region_not_in_set_is_denied(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _support_grant(priv)
    _, result = _resolve(ledger, dlg, pub, region="apac")
    assert result.outcome == "invalid"
    assert "region" in result.reason


def test_count_over_max_denied_and_min_enforced(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = _support_grant(priv)
    _, over = _resolve(ledger, dlg, pub, count="51")
    assert over.outcome == "invalid"
    _, under = _resolve(ledger, dlg, pub, count="0")
    assert under.outcome == "invalid"


def test_sum_max_on_non_monetary_field(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.ticket.purge", "system": "zendesk"}],
            "predicates": [
                {"type": "sum_max", "path": "/attributes/rows", "key": "purge_q4",
                 "max": "100"},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )

    def purge(rows, **extra):
        request = {
            "action": "support.ticket.purge", "system": "zendesk",
            "rows": rows, "budget_key": "purge_q4",
            "resource_type": "ticket", "resource_id": "bulk",
        }
        request.update(extra)
        return act(ledger, [dlg], request, PROFILE, pub)

    _, first = purge("60")
    assert first.outcome == "valid"
    # 60 + 30 = 90 within 100
    _, second = purge("30")
    assert second.outcome == "valid"
    _, denied = purge("20")  # 110 > 100
    assert denied.outcome == "invalid"
    assert "100" in denied.reason


def test_window_predicate_bounds_action_time(keys):
    priv, pub = keys
    ledger = Ledger()
    past = _iso(_now() - timedelta(days=2))
    future = _iso(_now() + timedelta(days=1))
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
            "predicates": [
                {"type": "window", "start": future, "end": _iso(_now() + timedelta(days=10))},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    request = {
        "action": "support.ticket.resolve", "system": "zendesk",
        "resource_type": "ticket", "resource_id": "t1", "region": "eu", "count": "1",
    }
    _, result = act(ledger, [dlg], request, PROFILE, pub)
    assert result.outcome == "invalid"
    assert "window" in result.reason


def test_approval_bound_to_envelope_digest(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.ticket.purge", "system": "zendesk"}],
            "predicates": [
                {"type": "cosign_above", "path": "/attributes/rows", "value": "50"},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    request = {
        "action": "support.ticket.purge", "system": "zendesk",
        "rows": "80", "resource_type": "ticket", "resource_id": "bulk",
    }
    # A digest of some *other* action must not satisfy the obligation.
    wrong = {
        "id": "apr_x", "delegation_id": dlg.id,
        "action": "support.ticket.purge",
        "envelope_digest": envelope_digest({**request, "rows": "10"}),
        "approver": "oidc|acme-retail|usr_8842", "nonce": "n1",
        "expires_at": _iso(_now() + timedelta(minutes=5)),
    }
    first, denied = act(ledger, [dlg], request, PROFILE, pub, approval=wrong)
    assert denied.outcome == "invalid"

    right = {**wrong, "id": "apr_y", "nonce": "n2", "envelope_digest": envelope_digest(request)}
    second, allowed = act(ledger, [dlg], request, PROFILE, pub, approval=right)
    assert allowed.outcome == "valid"
    assert any(o["status"] == "discharged" for o in second.decision["obligations"])


def test_expired_approval_rejected(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.ticket.purge", "system": "zendesk"}],
            "predicates": [
                {"type": "cosign_above", "path": "/attributes/rows", "value": "50"},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    request = {
        "action": "support.ticket.purge", "system": "zendesk",
        "rows": "80", "resource_type": "ticket", "resource_id": "bulk",
    }
    stale = {
        "id": "apr_z", "delegation_id": dlg.id, "action": "support.ticket.purge",
        "envelope_digest": envelope_digest(request),
        "approver": "oidc|acme-retail|usr_8842", "nonce": "n3",
        "expires_at": _iso(_now() - timedelta(minutes=1)),
    }
    _, result = act(ledger, [dlg], request, PROFILE, pub, approval=stale)
    assert result.outcome == "invalid"


def test_attenuation_generalizes_over_predicates(keys):
    priv, pub = keys
    parent = _support_grant(priv)

    # Child narrows the region set: allowed.
    narrow = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent-child",
        constraints={
            "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
            "predicates": [
                {"type": "in", "path": "/attributes/region", "values": ["eu"]},
                {"type": "max", "path": "/attributes/count", "value": "25"},
                {"type": "min", "path": "/attributes/count", "value": "1"},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=1)),
        parent=parent,
    )
    assert narrow.parent_delegation_id == parent.id

    # Child widens the region set beyond the parent: rejected.
    with pytest.raises(ValueError):
        create_delegation(
            priv,
            subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
            actor_id="support-agent-child",
            constraints={
                "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
                "predicates": [
                    {"type": "in", "path": "/attributes/region", "values": ["eu", "apac"]},
                ],
            },
            expires_at=_iso(_now() + timedelta(hours=1)),
            parent=parent,
        )


def test_predicate_not_in_profile_is_invalid(keys):
    priv, pub = keys
    ledger = Ledger()
    dlg = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="support-agent",
        constraints={
            "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
            "predicates": [
                {"type": "eq", "path": "/attributes/status", "value": "open"},
            ],
        },
        expires_at=_iso(_now() + timedelta(hours=2)),
    )
    profile = ValidationProfile.from_dict({
        **PROFILE.document(), "predicates": ["max", "sum_max"],
    })
    _, result = act(
        ledger, [dlg],
        {"action": "support.ticket.resolve", "system": "zendesk",
         "resource_type": "ticket", "resource_id": "t1", "status": "open"},
        profile, pub,
    )
    assert result.outcome == "invalid"
    assert "profile" in result.reason
