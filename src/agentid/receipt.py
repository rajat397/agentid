"""Receipts — the evidence artifact, hash-chained and tamper-evident."""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .crypto import b64url, canonical_json, digest_sha256


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Receipt:
    id: str
    issued_at: str
    fleet: str
    actor: dict[str, Any]
    delegation_id: str
    action: str
    resource: dict[str, Any]
    decision: dict[str, Any]
    outcome: dict[str, Any]
    action_type: str
    prev_hash: str
    signature_alg: str = "ES256"

    @property
    def body(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "action_type": self.action_type,
            "actor": self.actor,
            "decision": self.decision,
            "delegation_id": self.delegation_id,
            "fleet": self.fleet,
            "outcome": self.outcome,
            "prev_hash": self.prev_hash,
            "resource": self.resource,
        }

    @property
    def hash(self) -> str:
        return digest_sha256(canonical_json(self.body))

    def personal_data_refs(self) -> list[str]:
        return list(self.resource.get("attributes", {}).get("personal_data_refs", []))
