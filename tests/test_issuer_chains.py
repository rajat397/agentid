"""Per-hop issuer authentication — a chain of custody, not one key over a list.

Every hop is signed by its issuer's key, pinned in the parent's signed body.
Verification is fully offline: no JWKS fetch on the decision path.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.crypto import sign
from agentid.delegation import create_delegation
from agentid.flow import act, new_keys

PROFILE = ValidationProfile.example()
_HUMAN = {"type": "human", "id": "oidc|acme-retail|usr_8842"}


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _exp():
    return _iso(datetime.now(timezone.utc) + timedelta(hours=2))


def _grant(priv, actor_id, actor_pub=None, parent=None, **constraints):
    base = {
        "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
    }
    base.update(constraints)
    return create_delegation(
        priv, _HUMAN, actor_id, base, _exp(),
        parent=parent, actor_public_pem=actor_pub,
    )


def _request():
    return {
        "action": "support.ticket.resolve", "system": "zendesk",
        "resource_type": "ticket", "resource_id": "ticket_1001",
        "region": "eu", "count": "1",
    }


def test_three_hop_chain_with_distinct_issuer_keys():
    root_priv, root_pub = new_keys()
    agent_priv, agent_pub = new_keys()
    sub_priv, sub_pub = new_keys()

    root = _grant(root_priv, "agent", actor_pub=agent_pub)
    agent = _grant(agent_priv, "sub-agent", actor_pub=sub_pub, parent=root)
    sub = _grant(sub_priv, "worker", parent=agent)

    assert root.issuer["id"] == _HUMAN["id"]
    assert agent.issuer["id"] == "agent"
    assert sub.issuer["id"] == "sub-agent"
    assert root.actor["verification_key"] == agent_pub

    ledger = Ledger()
    _, result = act(ledger, [root, agent, sub], _request(), PROFILE, root_pub)
    assert result.outcome == "valid"


def test_child_signed_by_wrong_key_is_rejected():
    root_priv, root_pub = new_keys()
    agent_priv, agent_pub = new_keys()
    evil_priv, _ = new_keys()

    root = _grant(root_priv, "agent", actor_pub=agent_pub)
    with pytest.raises(ValueError, match="issuer key does not match"):
        _grant(evil_priv, "sub-agent", parent=root)


def test_forged_child_signature_is_rejected_at_its_hop():
    root_priv, root_pub = new_keys()
    agent_priv, agent_pub = new_keys()
    evil_priv, _ = new_keys()

    root = _grant(root_priv, "agent", actor_pub=agent_pub)
    child = _grant(agent_priv, "sub-agent", parent=root)
    forged = create_delegation(
        evil_priv, _HUMAN, "sub-agent",
        child.constraints, child.expires_at,
    )
    forged.issuer = dict(child.issuer)
    forged.signature = dict(child.signature)
    forged.signature["value"] = sign(evil_priv, forged.unsigned_body())

    ledger = Ledger()
    _, result = act(ledger, [root, forged], _request(), PROFILE, root_pub)
    assert result.outcome == "invalid"
    assert "signature" in result.reason


def test_child_without_parent_key_pin_falls_back_to_single_root_key():
    """Legacy grants remain verifiable, but cannot introduce a new issuer key."""
    root_priv, root_pub = new_keys()
    other_priv, _ = new_keys()

    root = _grant(root_priv, "agent")  # legacy: no pinned actor key
    child = _grant(other_priv, "sub-agent", parent=root)

    ledger = Ledger()
    _, result = act(ledger, [root, child], _request(), PROFILE, root_pub)
    assert result.outcome == "invalid"


def test_issuer_without_key_pin_is_rejected():
    root_priv, root_pub = new_keys()
    agent_priv, _ = new_keys()

    root = _grant(root_priv, "agent")  # no pin
    child = _grant(agent_priv, "sub-agent", parent=root)
    child.issuer = {"id": "agent", "kid": "key_legacy"}  # signed body no longer matches

    ledger = Ledger()
    _, result = act(ledger, [root, child], _request(), PROFILE, root_pub)
    assert result.outcome == "invalid"


def test_profile_chain_depth_is_enforced():
    privs = [new_keys() for _ in range(5)]
    root = _grant(privs[0][0], "a1", actor_pub=privs[1][1])
    d2 = _grant(privs[1][0], "a2", actor_pub=privs[2][1], parent=root)
    d3 = _grant(privs[2][0], "a3", actor_pub=privs[3][1], parent=d2)
    d4 = _grant(privs[3][0], "a4", parent=d3)

    ledger = Ledger()
    _, denied = act(ledger, [root, d2, d3, d4], _request(), PROFILE, privs[0][1])
    assert denied.outcome == "invalid"
    assert "chain depth" in denied.reason or "max_chain_length" in denied.reason


def test_key_rotation_requires_reissuing_the_parent_grant():
    root_priv, root_pub = new_keys()
    agent_priv, agent_pub = new_keys()
    rotated_priv, _ = new_keys()

    root = _grant(root_priv, "agent", actor_pub=agent_pub)
    with pytest.raises(ValueError, match="issuer key does not match"):
        _grant(rotated_priv, "sub-agent", parent=root)
