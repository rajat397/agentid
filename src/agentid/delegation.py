"""Delegation records — the authority chain, signed and attenuating.

Constraints use explicit (action, system) pairs; two independent lists would
imply a Cartesian product of scopes (RFC 8693 §2.1.1), which is the over-grant
this model exists to prevent. Amounts are decimal strings.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .crypto import canonical_json, digest_sha256, sign, verify


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _id(prefix: str, material: bytes) -> str:
    return f"{prefix}_{digest_sha256(material)[:16]}"


def _sub(actor_id: str) -> str:
    return f"spiffe://example.trust/agent/{actor_id}"


@dataclass
class Delegation:
    id: str
    subject: dict[str, Any]
    actor: dict[str, Any]
    parent_delegation_id: str | None
    chain_depth: int
    constraints: dict[str, Any]
    issued_at: str
    expires_at: str
    signature: dict[str, Any]

    @staticmethod
    def body(**kwargs: Any) -> dict[str, Any]:
        return {k: v for k, v in kwargs.items() if k not in ("signature",)}

    def unsigned_body(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "chain_depth": self.chain_depth,
            "constraints": self.constraints,
            "expires_at": self.expires_at,
            "id": self.id,
            "issued_at": self.issued_at,
            "parent_delegation_id": self.parent_delegation_id,
            "subject": self.subject,
        }


def create_delegation(
    private_pem: str,
    subject: dict[str, Any],
    actor_id: str,
    constraints: dict[str, Any],
    expires_at: str,
    parent: "Delegation | None" = None,
    validity_seconds: int = 900,
) -> Delegation:
    now = datetime.now(timezone.utc)
    issued = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    spiffe = _sub(actor_id)
    material = canonical_json([(subject or {}).get("id", ""), spiffe, issued, str(parent)])
    did = _id("dlg", material)
    depth = (parent.chain_depth + 1) if parent else 1

    # Attenuation: a child may never exceed its parent.
    if parent is not None:
        parent_perms = {(p["action"], p["system"]) for p in parent.constraints.get("permissions", [])}
        child_perms = {(p["action"], p["system"]) for p in constraints.get("permissions", [])}
        if not child_perms <= parent_perms:
            raise ValueError("child permissions exceed parent — attenuation violated")
        c_parent = Decimal(parent.constraints["max_amount"]["value"])
        c_child = Decimal(constraints["max_amount"]["value"])
        if c_child > c_parent:
            raise ValueError("child max_amount exceeds parent — attenuation violated")

    actor = {"type": "agent", "id": actor_id, "spiffe_id": spiffe}
    body = {
        "actor": actor,
        "chain_depth": depth,
        "constraints": constraints,
        "expires_at": expires_at,
        "id": did,
        "issued_at": issued,
        "parent_delegation_id": parent.id if parent else None,
        "subject": subject,
    }
    signature = {"alg": "ES256", "kid": "dlg-key-2026-11",
                 "value": sign(private_pem, body)}
    return Delegation(signature=signature, **body)


def verify_delegation(public_pem: str, d: Delegation) -> bool:
    return verify(public_pem, d.unsigned_body(), d.signature.get("value", ""))
