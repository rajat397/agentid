"""The action path: validate -> receipt -> append.

This is the slice the mutants exercise: a consequential action produces a
receipt, the receipt is hash-chained, and the decision is recorded with the
constraints evaluated and the obligations produced.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .crypto import generate_keypair
from .delegation import create_delegation
from .ledger import Ledger
from .profile import ValidationProfile
from .receipt import Receipt
from .validator import ValidationResult, validate


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_keys() -> tuple[str, str]:
    return generate_keypair()


def make_agent(agent_id: str) -> tuple[str, str]:
    return new_keys()


def act(
    ledger: Ledger,
    chain,
    action_request: dict[str, Any],
    profile: ValidationProfile,
    public_pem: str,
    fleet: str = "marketing",
    approval: dict[str, Any] | None = None,
    at: str | None = None,
    revoked: set[str] | None = None,
) -> tuple[Receipt, ValidationResult]:
    result = validate(chain, action_request, profile, public_pem,
                      ledger=ledger, approval=approval, at=at, revoked=revoked)
    prev_hash = ledger.receipts[-1].hash if ledger.receipts else "0" * 64
    decision = {
        "result": "allowed" if result.outcome == "valid" else "denied",
        "outcome": result.outcome,
        "reason": result.reason,
        "constraints_evaluated": result.constraints_evaluated,
        "obligations": result.obligations,
    }
    receipt = Receipt(
        id="",
        issued_at=_now(),
        fleet=fleet,
        actor={
            "spiffe_id": chain[-1].actor["spiffe_id"],
            "agent_id": chain[-1].actor["id"],
            "credential_kid": chain[-1].signature.get("kid", "dlg-key-2026-11"),
        },
        delegation_id=chain[-1].id,
        action=action_request["action"],
        resource={
            "type": action_request.get("resource_type", "resource"),
            "id": action_request.get("resource_id", "unspecified"),
            "attributes": {
                "amount": action_request.get("amount"),
                "currency": action_request.get("currency", "USD"),
                "budget_key": (action_request.get("budget_key") or ""),
                "personal_data_refs": action_request.get("personal_data_refs", []),
            },
            "amount": action_request.get("amount", "0"),
            "currency": action_request.get("currency", "USD"),
        },
        decision=decision,
        outcome={"status": "succeeded" if result.outcome == "valid" else "blocked",
                 "external_ref": action_request.get("external_ref"),
                 "blocked": result.outcome != "valid"},
        action_type="observed",
        prev_hash=prev_hash,
    )
    ledger.append(receipt)
    return receipt, result
