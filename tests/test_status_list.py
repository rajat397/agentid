"""IETF Token Status List (draft-21) — wire format and fail-closed enforcement.

REVOKED / SUSPENDED statuses must stop an action at the PEP; stale, tampered
or malformed status tokens must never be treated as VALID.
"""

import base64
import json
import time

import pytest

from agentid import Ledger, ValidationProfile
from agentid.crypto import generate_keypair
from agentid.delegation import create_delegation
from agentid.flow import act
from agentid.signing import DevSigner
from agentid.status import (
    build_status_token,
    check_status,
    decode_status_list,
    encode_status_list,
    verify_status_token,
)

PROFILE = ValidationProfile.example()
_HUMAN = {"type": "human", "id": "oidc|acme-retail|usr_8842"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def test_bitset_round_trip_lsb_first():
    statuses = [0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x00, 0x01]
    encoded = encode_status_list(statuses)
    assert encoded["bits"] == 2
    assert decode_status_list(encoded, len(statuses)) == statuses


def test_signed_status_token_verifies_and_exposes_claims():
    priv, pub = generate_keypair()
    signer = DevSigner(priv, pub, kid="status_key", warn=False)
    now = int(time.time())
    token = build_status_token(
        "https://example.invalid/status/fleet",
        [0x00, 0x01, 0x02], signer,
        iat=now, exp=now + 600, ttl=300,
    )
    header, payload, _ = token.split(".")
    assert json.loads(_b64url_decode(header))["typ"] == "statuslist+jwt"
    verified = verify_status_token(token, signer.public_keys(), now=now, max_status_age=300)
    assert verified["status_list"]["bits"] == 2
    assert verified["status_count"] == 3


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def test_tampered_status_token_is_rejected():
    priv, pub = generate_keypair()
    signer = DevSigner(priv, pub, kid="status_key", warn=False)
    now = int(time.time())
    token = build_status_token("uri", [0x00, 0x01], signer,
                               iat=now, exp=now + 600, ttl=300)
    parts = token.split(".")
    payload = json.loads(_b64url_decode(parts[1]))
    payload["status_list"]["lst"] = encode_status_list([0x00, 0x00])["lst"]
    parts[1] = _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(ValueError, match="signature"):
        verify_status_token(".".join(parts), signer.public_keys(), now=now, max_status_age=300)


def test_stale_status_token_is_rejected():
    priv, pub = generate_keypair()
    signer = DevSigner(priv, pub, kid="status_key", warn=False)
    now = int(time.time())
    token = build_status_token("uri", [0x00], signer,
                               iat=now - 1000, exp=now + 600, ttl=300)
    with pytest.raises(ValueError, match="stale"):
        verify_status_token(token, signer.public_keys(), now=now, max_status_age=300)


def test_check_status_reads_index_and_refuses_out_of_range():
    priv, pub = generate_keypair()
    signer = DevSigner(priv, pub, kid="status_key", warn=False)
    now = int(time.time())
    token = build_status_token("uri", [0x00, 0x01, 0x02], signer,
                               iat=now, exp=now + 600, ttl=300)
    assert check_status(token, 1, signer.public_keys(), max_status_age=300, now=now) == 0x01
    with pytest.raises(ValueError, match="index"):
        check_status(token, 99, signer.public_keys(), max_status_age=300, now=now)


def _grant(priv, pub, status_idx=None):
    constraints = {"permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}]}
    dlg = create_delegation(
        priv, _HUMAN, "agent", constraints,
        "2030-01-01T00:00:00Z", status_idx=status_idx,
    )
    return dlg


def _request():
    return {
        "action": "support.ticket.resolve", "system": "zendesk",
        "resource_type": "ticket", "resource_id": "t1", "count": "1",
    }


def test_revoked_and_suspended_delegations_are_denied():
    priv, pub = generate_keypair()
    for status in (0x01, 0x02):
        dlg = _grant(priv, pub, status_idx=0)
        ledger = Ledger()
        _, result = act(ledger, [dlg], _request(), PROFILE, pub,
                        status_lookup=lambda uri, idx: status)
        assert result.outcome == "invalid"
        assert "status" in result.reason


def test_valid_status_allows_action_and_missing_lookup_fails_closed():
    priv, pub = generate_keypair()
    dlg = _grant(priv, pub, status_idx=0)
    _, allowed = act(Ledger(), [dlg], _request(), PROFILE, pub,
                     status_lookup=lambda uri, idx: 0x00)
    assert allowed.outcome == "valid"

    _, denied = act(Ledger(), [dlg], _request(), PROFILE, pub)
    assert denied.outcome == "invalid"
    assert "lookup" in denied.reason
