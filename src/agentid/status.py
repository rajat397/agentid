"""IETF Token Status List (draft-ietf-oauth-status-list-21) wire format.

A small, self-contained encoder/decoder and signed `statuslist+jwt`
generator/verifier. This is a wire-format adapter, not a revocation policy:
status 0x01/0x02 denial and freshness bounds live in the validator.

Our one extension claim is `status_count`, which makes the compressed bitset
self-describing for offline verification. It is documented as an extension,
not as part of the IETF draft.
"""

import base64
import json
import time
import zlib
from typing import Any

from .crypto import verify_raw
from .signing import Signer

BITS = 2
VALID = 0x00
REVOKED = 0x01
SUSPENDED = 0x02


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def encode_status_list(statuses: list[int], bits: int = BITS) -> dict[str, Any]:
    """Pack statuses LSB-first into bytes, ZLIB-compress, base64url encode."""
    if bits not in (1, 2, 4, 8):
        raise ValueError("bits must be 1, 2, 4 or 8")
    per_byte = 8 // bits
    raw = bytearray((len(statuses) + per_byte - 1) // per_byte)
    for i, status in enumerate(statuses):
        if not 0 <= status < (1 << bits):
            raise ValueError(f"status {status} does not fit in {bits} bits")
        raw[i // per_byte] |= status << ((i % per_byte) * bits)
    return {"bits": bits, "lst": _b64url(zlib.compress(bytes(raw), 9))}


def decode_status_list(status_list: dict[str, Any], count: int) -> list[int]:
    bits = status_list["bits"]
    raw = zlib.decompress(_unb64url(status_list["lst"]))
    per_byte = 8 // bits
    mask = (1 << bits) - 1
    out = []
    for i in range(count):
        byte = raw[i // per_byte] if i // per_byte < len(raw) else 0
        out.append((byte >> ((i % per_byte) * bits)) & mask)
    return out


def build_status_token(
    uri: str,
    statuses: list[int],
    signer: Signer,
    iat: int | None = None,
    exp: int | None = None,
    ttl: int = 300,
) -> str:
    """Return compact JWS-shaped `statuslist+jwt` signed by `signer`."""
    now = int(time.time())
    header = {"alg": "ES256", "typ": "statuslist+jwt", "kid": signer.kid}
    payload = {
        "sub": uri,
        "iat": iat if iat is not None else now,
        "exp": exp if exp is not None else now + ttl * 2,
        "ttl": ttl,
        "status_list": encode_status_list(statuses),
        "status_count": len(statuses),
    }
    signing_input = (
        _b64url(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    )
    return signing_input + "." + signer.sign_raw(signing_input.encode("ascii"))


def verify_status_token(
    token: str,
    public_keys: dict[str, str],
    now: int | None = None,
    max_status_age: int = 300,
) -> dict[str, Any]:
    """Verify signature, header and freshness; return the payload."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed statuslist+jwt")
    header_b64, payload_b64, signature = parts
    try:
        header = json.loads(_unb64url(header_b64))
        payload = json.loads(_unb64url(payload_b64))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("malformed statuslist+jwt") from exc
    if header.get("typ") != "statuslist+jwt" or header.get("alg") != "ES256":
        raise ValueError("unsupported statuslist+jwt header")
    pem = public_keys.get(header.get("kid", ""))
    if not pem:
        raise ValueError("unknown status signing key")
    if not verify_raw(pem, f"{header_b64}.{payload_b64}".encode("ascii"), signature):
        raise ValueError("invalid statuslist+jwt signature")
    current = now if now is not None else int(time.time())
    issued = int(payload.get("iat", 0))
    if current < issued or current - issued > min(int(payload.get("ttl", 0)) or max_status_age,
                                                 max_status_age):
        raise ValueError("stale statuslist+jwt")
    if payload.get("exp") and current > int(payload["exp"]):
        raise ValueError("stale statuslist+jwt (expired)")
    if "status_list" not in payload or "status_count" not in payload:
        raise ValueError("malformed statuslist+jwt (missing status fields)")
    return payload


def check_status(
    token: str,
    idx: int,
    public_keys: dict[str, str],
    max_status_age: int = 300,
    now: int | None = None,
) -> int:
    """Resolve one status, or fail closed with ValueError."""
    payload = verify_status_token(token, public_keys, now=now,
                                  max_status_age=max_status_age)
    count = int(payload["status_count"])
    if not 0 <= idx < count:
        raise ValueError(f"status index {idx} out of range")
    return decode_status_list(payload["status_list"], count)[idx]
