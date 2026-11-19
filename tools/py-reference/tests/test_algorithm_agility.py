"""Algorithm agility — profile allowlist and dual-sign without format change.

No PQ crypto is shipped; this pins the migration shape so adding ML-DSA later
does not require reworking receipts or verification.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agentid import Ledger, ValidationProfile
from agentid.crypto import generate_keypair
from agentid.delegation import create_delegation
from agentid.flow import act
from agentid.signing import DevSigner, dual_sign

PROFILE = ValidationProfile.example()
_HUMAN = {"type": "human", "id": "oidc|acme-retail|usr_8842"}


def _grant(priv, pub, alg=None):
    dlg = create_delegation(
        priv, _HUMAN, "agent",
        {"permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}]},
        "2030-01-01T00:00:00Z",
    )
    if alg is not None:
        dlg.signature["alg"] = alg
    return dlg


def _request():
    return {
        "action": "support.ticket.resolve", "system": "zendesk",
        "resource_type": "ticket", "resource_id": "t1", "count": "1",
    }


def test_profile_rejects_algorithm_outside_allowlist():
    priv, pub = generate_keypair()
    dlg = _grant(priv, pub, alg="EXPERIMENTAL-ALG")
    _, result = act(Ledger(), [dlg], _request(), PROFILE, pub)
    assert result.outcome == "invalid"
    assert "algorithm" in result.reason


def test_profile_allowlist_is_part_of_profile_digest():
    base = ValidationProfile.example().document()
    with_alg = ValidationProfile.from_dict({**base, "signature_algs": ["ES256", "ML-DSA-65"]})
    assert with_alg.digest != ValidationProfile.from_dict(base).digest
    assert with_alg.signature_algs == ("ES256", "ML-DSA-65")


def test_dual_sign_returns_two_signatures_without_changing_receipt_shape():
    priv, pub = generate_keypair()
    signer = DevSigner(priv, pub, kid="es_key", warn=False)

    class StubPQSigner(DevSigner):
        """Format-only stub — no PQ cryptography is claimed."""

        def sign(self, payload):
            sig = super().sign(payload)
            return {**sig, "alg": "ML-DSA-65", "kid": "pq_key_stub"}

    pq = StubPQSigner(priv, pub, kid="pq_key_stub", warn=False)
    signatures = dual_sign({"action": "a"}, [signer, pq])
    assert {s["alg"] for s in signatures} == {"ES256", "ML-DSA-65"}

    dlg = _grant(priv, pub)
    receipt, result = act(Ledger(), [dlg], _request(), PROFILE, pub,
                          signer=signer, extra_signers=[pq])
    assert result.outcome == "valid"
    assert receipt.signature["alg"] == "ES256"
    assert {s["alg"] for s in receipt.signatures} == {"ES256", "ML-DSA-65"}
