"""Cryptographic primitives.

ES256 (ECDSA P-256 + SHA-256) for delegation and receipt signing,
canonical JSON for signature input (RFC 8785-compatible subset),
and SHA-256 for the hash chain and profile content-addressing.
"""

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON: sorted keys, compact separators, ASCII, no floats.

    Amounts are decimal strings by policy; this encoder would reject floats,
    which is why float amounts are impossible in signed artifacts.
    """

    def _default(o: Any) -> Any:
        raise TypeError(f"unserializable type: {type(o)!r} — amounts must be decimal strings")

    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_default,
    ).encode("utf-8")


def digest_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64url_digest_sha256(data: bytes) -> str:
    return b64url(hashlib.sha256(data).digest())


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem)."""
    private = ec.generate_private_key(ec.SECP256R1())
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _load_private(pem: str) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


def _load_public(pem: str) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(pem.encode("utf-8"))


def sign(private_pem: str, payload: dict) -> str:
    key = _load_private(private_pem)
    sig = key.sign(canonical_json(payload), ec.ECDSA(hashes.SHA256()))
    return b64url(sig)


def verify(public_pem: str, payload: dict, signature: str) -> bool:
    try:
        sig = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        _load_public(public_pem).verify(sig, canonical_json(payload), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
