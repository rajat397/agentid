"""Append-only receipt ledger — the tamper-evident audit trail.

The PEP writes receipts; the agent never does. Chain verification recomputes
every hash and checks each `prev_hash` links correctly.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .crypto import canonical_json, digest_sha256, verify
from .receipt import Receipt


@dataclass
class Ledger:
    receipts: list[Receipt] = field(default_factory=list)

    def append(self, receipt: Receipt) -> Receipt:
        prev = self.receipts[-1].hash if self.receipts else "0" * 64
        if receipt.prev_hash != prev:
            raise ValueError("prev_hash does not match the current chain head")
        if not receipt.id:
            receipt.id = f"rcp_{digest_sha256(canonical_json(receipt.body))[:16]}"
        self.receipts.append(receipt)
        return receipt

    def verify_chain(self, public_keys: dict[str, str] | None = None) -> tuple[bool, list[str]]:
        problems: list[str] = []
        expected = "0" * 64
        for i, r in enumerate(self.receipts):
            if r.prev_hash != expected:
                problems.append(f"receipt[{i}] prev_hash broken: expected {expected[:12]}… got {r.prev_hash[:12]}…")
                break
            if r.signature is not None:
                if public_keys is None:
                    problems.append(f"receipt[{i}] signature not verified: no public keys supplied")
                else:
                    pem = public_keys.get(r.signature.get("kid", ""))
                    if not pem or not verify(pem, r.body, r.signature.get("value", "")):
                        problems.append(f"receipt[{i}] signature invalid or kid unknown")
            expected = r.hash
        if not self.receipts:
            problems.append("ledger is empty")
        return (not problems, problems)

    def query(self, **filters: Any) -> list[Receipt]:
        def match(r: Receipt) -> bool:
            for key, want in filters.items():
                if key == "action" and r.action != want:
                    return False
                if key == "fleet" and r.fleet != want:
                    return False
                if key == "result" and r.decision.get("result") != want:
                    return False
                if key == "delegation_id" and r.delegation_id != want:
                    return False
                if key == "personal_data_ref" and want not in self.receipts_personal_refs(r):
                    return False
            return True

        return [r for r in self.receipts if match(r)]

    @staticmethod
    def receipts_personal_refs(r: Receipt) -> list[str]:
        return list(r.resource.get("attributes", {}).get("personal_data_refs", []))

    def total_for(self, path: str, key: str, period_start_iso: str,
                  currency: str | None = None) -> str:
        """Sum one numeric attribute path for a root key within a period.

        `path` is a pointer into the action envelope (e.g. /attributes/amount
        or /attributes/rows); receipts record the envelope attributes.
        """
        from decimal import Decimal

        from .constraints import resolve

        total = Decimal("0")
        for r in self.receipts:
            if r.decision.get("result") != "allowed":
                continue
            attributes = r.resource.get("attributes", {})
            if attributes.get("budget_key") != key:
                continue
            if currency is not None and attributes.get("currency") != currency:
                continue
            if r.issued_at < period_start_iso:
                continue
            try:
                value = resolve({"attributes": attributes}, path)
            except (KeyError, IndexError, ValueError, TypeError):
                continue
            total += Decimal(str(value))
        return format(total, ".2f")

    def total_spend(self, root_budget: str, period_start_iso: str, currency: str) -> str:
        return self.total_for("/attributes/amount", root_budget, period_start_iso, currency)

    def personal_data_index(self) -> dict[str, list[Receipt]]:
        """Map personal_data_ref -> receipts touching it (for GDPR Art. 17)."""
        idx: dict[str, list[Receipt]] = {}
        for r in self.receipts:
            for ref in self.receipts_personal_refs(r):
                idx.setdefault(ref, []).append(r)
        return idx
