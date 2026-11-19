"""The action path: validate -> receipt -> append.

This is the slice the mutants exercise: a consequential action produces a
receipt, the receipt is hash-chained, and the decision is recorded with the
constraints evaluated and the obligations produced.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Callable
from typing import Any

from .crypto import generate_keypair
from .envelope import build as build_envelope, digest as envelope_digest
from .delegation import create_delegation
from .ledger import Ledger
from .profile import ValidationProfile
from .signing import Signer, dual_sign
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
    signer: Signer | None = None,
    status_lookup: Callable[[str, int], int] | None = None,
    extra_signers: list[Signer] | None = None,
) -> tuple[Receipt, ValidationResult]:
    result = validate(chain, action_request, profile, public_pem,
                      ledger=ledger, approval=approval, at=at, revoked=revoked,
                      public_keys=signer.public_keys() if signer is not None else None,
                      status_lookup=status_lookup)
    prev_hash = ledger.receipts[-1].hash if ledger.receipts else "0" * 64
    envelope_attributes = build_envelope(action_request)["attributes"]
    decision = {
        "result": "allowed" if result.outcome == "valid" else "denied",
        "outcome": result.outcome,
        "reason": result.reason,
        "envelope_digest": envelope_digest(action_request),
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
                **envelope_attributes,
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
    if signer is not None:
        receipt.signature = signer.sign(receipt.body)
        if extra_signers:
            receipt.signatures = dual_sign(receipt.body, [signer, *extra_signers])
    ledger.append(receipt)
    return receipt, result
