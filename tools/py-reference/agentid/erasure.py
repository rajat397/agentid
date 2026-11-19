"""GDPR Art. 17 erasure planning over the receipt ledger.

The control plane holds references, not the customer's data. An erasure
request enumerates everything the agents touched and produces a plan with
deadlines and evidence — never deletes anything itself.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .ledger import Ledger


@dataclass
class ErasurePlan:
    subject_id: str
    created_at: str
    deadline: str
    days_remaining: int
    receipts: list[dict[str, Any]] = field(default_factory=list)
    delegations: list[str] = field(default_factory=list)
    downstream_systems: list[dict[str, Any]] = field(default_factory=list)
    derived_artifacts: list[dict[str, Any]] = field(default_factory=list)
    total_receipts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "created_at": self.created_at,
            "deadline": self.deadline,
            "days_remaining": self.days_remaining,
            "total_receipts": self.total_receipts,
            "delegations": self.delegations,
            "downstream_systems": self.downstream_systems,
            "derived_artifacts": self.derived_artifacts,
        }


def build_erasure_plan(
    ledger: Ledger,
    subject_id: str,
    data_source_registry: dict[str, list[dict[str, Any]]],
    derived_artifacts: list[dict[str, Any]],
    jurisdiction: str = "EU",
) -> ErasurePlan:
    """Enumerate everything touching `subject_id` and build the erasure plan.

    `data_source_registry` maps personal_data_ref -> list of downstream
    systems holding records derived from that subject. It is supplied by the
    customer — the plan is only as good as their registry.
    """
    now = datetime.now(timezone.utc)
    created = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    deadline = (now + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")

    idx = ledger.personal_data_index()
    hits = idx.get(subject_id, [])

    delegations = sorted({r.delegation_id for r in hits})
    downstream: dict[str, dict[str, Any]] = {}
    for r in hits:
        for ref in ledger.receipts_personal_refs(r):
            for entry in data_source_registry.get(ref, []):
                key = entry["system"]
                downstream.setdefault(key, {"system": key, "records": 0,
                                            "deletion_method": entry.get("method", "customer_connector")})
                downstream[key]["records"] += int(entry.get("records", 1))

    receipts_desc = [
        {
            "receipt_id": r.id,
            "action": r.action,
            "fleet": r.fleet,
            "issued_at": r.issued_at,
            "refs": ledger.receipts_personal_refs(r),
            "result": r.decision.get("result"),
        }
        for r in hits
    ]

    return ErasurePlan(
        subject_id=subject_id,
        created_at=created,
        deadline=deadline,
        days_remaining=30,
        receipts=receipts_desc,
        delegations=delegations,
        downstream_systems=list(downstream.values()),
        derived_artifacts=derived_artifacts,
        total_receipts=len(hits),
    )
