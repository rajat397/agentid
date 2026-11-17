"""Deterministic validation — the Validator split from the RP policy step.

Per the mechanism in draft-hulea-wimse-agent-mandate-01: evidence in,
`valid` | `invalid` | `indeterminate` plus Obligations out. No business
policy here; the relying party applies its own policy to this result.

Constraints use explicit (action, system) pairs. Amounts are decimal strings.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .crypto import verify
from .delegation import Delegation
from .ledger import Ledger
from .profile import ValidationProfile


@dataclass
class ValidationResult:
    outcome: str  # "valid" | "invalid" | "indeterminate"
    reason: str
    obligations: list[dict[str, Any]] = field(default_factory=list)
    constraints_evaluated: list[dict[str, Any]] = field(default_factory=list)


def _parse(iso: str) -> datetime:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _dec(v: Any) -> Decimal:
    return Decimal(str(v))


def validate(
    chain: list[Delegation],
    action_request: dict[str, Any],
    profile: ValidationProfile,
    public_pem: str,
    ledger: Ledger | None = None,
    approval: dict[str, Any] | None = None,
    at: str | None = None,
    revoked: set[str] | None = None,
) -> ValidationResult:
    now = _parse(at) if at else datetime.now(timezone.utc)

    if not chain:
        return ValidationResult("invalid", "empty delegation chain")
    if revoked and chain[-1].id in revoked:
        return ValidationResult("invalid", "leaf delegation has been revoked")
    if len(chain) > profile.max_chain_length:
        return ValidationResult(
            "invalid",
            f"chain depth {len(chain)} exceeds profile max_chain_length {profile.max_chain_length}",
        )

    # 1. Signatures
    for i, d in enumerate(chain):
        if not verify(public_pem, d.unsigned_body(), d.signature.get("value", "")):
            return ValidationResult("invalid", f"invalid signature at chain hop {i + 1}")

    # 2. Attenuation: every child must be within its parent
    for parent, child in zip(chain, chain[1:]):
        parent_perms = {(p["action"], p["system"]) for p in parent.constraints.get("permissions", [])}
        child_perms = {(p["action"], p["system"]) for p in child.constraints.get("permissions", [])}
        if not child_perms <= parent_perms:
            return ValidationResult(
                "invalid",
                "attenuation violated: child permissions exceed parent",
            )
        if _dec(child.constraints["max_amount"]["value"]) > _dec(parent.constraints["max_amount"]["value"]):
            return ValidationResult(
                "invalid",
                "attenuation violated: child max_amount exceeds parent",
            )
        if _parse(child.expires_at) > _parse(parent.expires_at):
            return ValidationResult(
                "invalid",
                "attenuation violated: child expiry exceeds parent",
            )

    # 3. Leaf must be valid in time
    leaf = chain[-1]
    if _parse(leaf.expires_at) < now:
        return ValidationResult("invalid", "delegation expired")

    # 4. Permission check — explicit (action, system) pair
    perms = {(p["action"], p["system"]) for p in leaf.constraints.get("permissions", [])}
    want = (action_request["action"], action_request["system"])
    evaluated = [{"constraint": "permission", "pair": list(want), "satisfied": want in perms}]
    if want not in perms:
        return ValidationResult("invalid", "action/system not permitted by delegation", constraints_evaluated=evaluated)

    # 5. Budget check — root-keyed, shared across the chain (sum_max)
    amount = _dec(action_request["amount"])
    currency = action_request.get("currency", "USD")
    budget = leaf.constraints.get("budget")
    if budget:
        budget_key = budget.get("key", "budget")
        budget_cap = _dec(budget["value"])
        period_start = action_request.get("period_start", "1970-01-01T00:00:00Z")
        spent = Decimal("0")
        if ledger is not None:
            spent = _dec(ledger.total_spend(budget_key, period_start, currency))
        remaining = budget_cap - spent
        evaluated.append({"constraint": "sum_max", "budget": budget_key,
                          "cap": str(budget_cap), "spent": str(spent),
                          "remaining": str(remaining), "satisfied": amount <= remaining})
        if amount > remaining:
            return ValidationResult(
                "invalid",
                f"budget exhausted: {spent + amount} exceeds cap {budget_cap} for {budget_key}",
                constraints_evaluated=evaluated,
            )

    # 6. Amount cap — max_amount (hard ceiling, independent of budget)
    cap = _dec(leaf.constraints["max_amount"]["value"])
    evaluated.append({"constraint": "max_amount", "bound": str(cap), "observed": str(amount),
                      "satisfied": amount <= cap})
    if amount > cap:
        return ValidationResult("invalid", f"amount {amount} exceeds cap {cap}",
                                constraints_evaluated=evaluated)

    # 7. Human approval above threshold — produces an Obligation
    threshold = _dec(leaf.constraints["requires_human_approval_above"]["value"])
    approval_needed = amount > threshold
    obligations: list[dict[str, Any]] = []
    evaluated.append({"constraint": "requires_human_approval_above",
                      "bound": str(threshold), "observed": str(amount),
                      "satisfied": not approval_needed})
    if approval_needed:
        if approval is None:
            return ValidationResult(
                "indeterminate",
                f"amount {amount} exceeds approval threshold {threshold}; no approval supplied",
                obligations=[{"type": "cosign_above", "value": str(threshold),
                              "observed": str(amount), "status": "required"}],
                constraints_evaluated=evaluated,
            )
        ok = (
            approval.get("delegation_id") == leaf.id
            and approval.get("action") == action_request["action"]
            and _dec(approval.get("amount", "0")) >= amount
            and approval.get("approver")  # approver identity required
            and approval.get("nonce")     # non-forgeable request nonce
        )
        evaluated.append({"constraint": "approval", "approval_id": approval.get("id"),
                          "satisfied": ok})
        if not ok:
            return ValidationResult(
                "invalid",
                "approval does not satisfy the cosign_above obligation",
                constraints_evaluated=evaluated,
            )
        obligations.append({"type": "cosign_above", "value": str(threshold),
                            "observed": str(amount), "status": "discharged",
                            "approval_id": approval.get("id")})

    return ValidationResult("valid", "within constraints",
                            obligations=obligations,
                            constraints_evaluated=evaluated)
