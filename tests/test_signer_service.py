"""Credential service — signer boundary, real receipt signatures, rotation.

Exit condition: receipts produced through the signer carry a verifiable ES256
signature; KMS/HSM adapters need no private key in process memory; rotated
keys remain verifiable inside the published overlap window; unsigned legacy
receipts still verify their chain and are labeled as such.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.crypto import canonical_json, generate_keypair, verify
from agentid.delegation import create_delegation
from agentid.flow import act
from agentid.signing import DevSigner, ExternalSigner, RotatingSigner

PROFILE = ValidationProfile.example()
_HUMAN = {"type": "human", "id": "oidc|acme-retail|usr_8842"}


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _grant(signer=None, priv=None, pub=None, actor_pub=None):
    return create_delegation(
        priv if signer is None else "",
        _HUMAN, "agent",
        {"permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}]},
        _iso(datetime.now(timezone.utc) + timedelta(hours=2)),
        signer=signer, actor_public_pem=actor_pub,
    )


@pytest.fixture
def dev_signer():
    priv, pub = generate_keypair()
    return DevSigner(priv, pub, kid="dev_key_1", warn=False)


def test_dev_signer_signs_and_verifies(dev_signer):
    payload = {"action": "support.ticket.resolve", "count": "1"}
    signature = dev_signer.sign(payload)
    assert signature["kid"] == dev_signer.kid
    assert verify(dev_signer.public_key(signature["kid"]), payload, signature["value"])


def test_receipt_is_actually_signed_and_chain_verifies(dev_signer):
    priv, pub = generate_keypair()
    dlg = _grant(signer=dev_signer)
    ledger = Ledger()
    receipt, result = act(
        ledger, [dlg],
        {"action": "support.ticket.resolve", "system": "zendesk",
         "resource_type": "ticket", "resource_id": "t1", "count": "1"},
        PROFILE, pub, signer=dev_signer,
    )
    assert result.outcome == "valid"
    assert receipt.signature["kid"] == dev_signer.kid
    ok, problems = ledger.verify_chain(public_keys=dev_signer.public_keys())
    assert ok, problems


def test_tampered_receipt_signature_is_detected(dev_signer):
    priv, pub = generate_keypair()
    dlg = _grant(signer=dev_signer)
    ledger = Ledger()
    receipt, _ = act(
        ledger, [dlg],
        {"action": "support.ticket.resolve", "system": "zendesk",
         "resource_type": "ticket", "resource_id": "t1", "count": "1"},
        PROFILE, pub, signer=dev_signer,
    )
    receipt.signature["value"] = "tampered"
    ok, problems = ledger.verify_chain(public_keys=dev_signer.public_keys())
    assert not ok
    assert any("signature" in p for p in problems)


def test_external_signer_needs_no_private_key_in_object():
    """KMS/HSM adapter shape: only a sign callable and the published public key."""
    priv, pub = generate_keypair()

    def kms_sign(payload_bytes: bytes) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        from agentid.crypto import _load_private
        return _load_private(priv).sign(payload_bytes, ec.ECDSA(hashes.SHA256()))

    signer = ExternalSigner("kms_key_1", pub, kms_sign)
    assert not hasattr(signer, "private_pem")
    signature = signer.sign({"action": "a"})
    assert signature["kid"] == "kms_key_1"
    assert verify(pub, {"action": "a"}, signature["value"])


def test_rotation_overlap_keeps_old_signatures_verifiable():
    old_priv, old_pub = generate_keypair()
    new_priv, new_pub = generate_keypair()
    old = DevSigner(old_priv, old_pub, kid="key_old", warn=False)
    new = DevSigner(new_priv, new_pub, kid="key_new", warn=False)
    rotating = RotatingSigner([new, old])

    signed_old = old.sign({"action": "old"})
    signed_new = rotating.sign({"action": "new"})
    assert signed_new["kid"] == "key_new"
    keys = rotating.public_keys()
    assert verify(keys["key_old"], {"action": "old"}, signed_old["value"])
    assert verify(keys["key_new"], {"action": "new"}, signed_new["value"])


def test_unsigned_legacy_receipt_still_verifies_chain():
    priv, pub = generate_keypair()
    dlg = _grant(priv=priv, pub=pub)
    ledger = Ledger()
    receipt, _ = act(
        ledger, [dlg],
        {"action": "support.ticket.resolve", "system": "zendesk",
         "resource_type": "ticket", "resource_id": "t1", "count": "1"},
        PROFILE, pub,
    )
    assert receipt.signature is None
    ok, problems = ledger.verify_chain()
    assert ok, problems
