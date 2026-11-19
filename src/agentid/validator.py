"""Deterministic validation — the Validator split from the RP policy step.

Per the mechanism in draft-hulea-wimse-agent-mandate-01: evidence in,
`valid` | `invalid` | `indeterminate` plus Obligations out. No business
policy here; the relying party applies its own policy to this result.

Constraints are explicit (action, system) permissions plus predicates over
attribute paths of the canonical action envelope (see constraints.py).
Legacy money-first keys are translated, so previously issued grants verify.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from . import envelope
from .constraints import attenuation_violation, evaluate, normalize, resolve
from .crypto import key_fingerprint, verify
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


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _dec(v: Any) -> Decimal:
    return Decimal(str(v))


def _check_approval(
    approval: dict[str, Any] | None,
    leaf: Delegation,
    action_request: dict[str, Any],
    atom: dict[str, Any],
    observed: Any,
    now: datetime,
) -> tuple[bool, str]:
    if not isinstance(approval, dict):
        return False, "no approval supplied"
    if approval.get("delegation_id") != leaf.id:
        return False, "approval names a different delegation"
    if approval.get("action") != action_request["action"]:
        return False, "approval names a different action"
    if not approval.get("approver"):
        return False, "approval has no approver identity"
    if not approval.get("nonce"):
        return False, "approval has no nonce"
    if approval.get("expires_at") and _parse(approval["expires_at"]) < now:
        return False, "approval expired"
    digest = approval.get("envelope_digest")
    if digest is not None:
        if digest != envelope.digest(action_request):
            return False, "approval digest does not bind this action envelope"
        return True, "envelope-bound approval"
    # Legacy approval shape: numeric satisfaction on the amount attribute.
    if atom["path"] == "/attributes/amount" and approval.get("amount") is not None:
        if _dec(approval["amount"]) >= _dec(observed):
            return True, "legacy amount approval"
        return False, "approval amount is below the action"
    return False, "approval does not bind an action envelope"


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

    # 1. Signatures — each hop is verified by its issuer's key. For new-style
    # grants that key is pinned in the parent's signed body (fully offline);
    # legacy grants fall back to the caller-supplied root key.
    for i, d in enumerate(chain):
        if i == 0:
            key = public_pem
        else:
            parent = chain[i - 1]
            pinned = parent.actor.get("verification_key")
            issuer = getattr(d, "issuer", None)
            if pinned:
                if not issuer or issuer.get("id") != parent.actor.get("id"):
                    return ValidationResult(
                        "invalid",
                        f"chain hop {i + 1} issuer does not match parent actor",
                    )
                if issuer.get("kid") != key_fingerprint(pinned):
                    return ValidationResult(
                        "invalid",
                        f"chain hop {i + 1} issuer key id does not match parent pin",
                    )
                key = pinned
            else:
                if issuer:
                    return ValidationResult(
                        "invalid",
                        f"chain hop {i + 1} has an issuer but no parent key pin",
                    )
                key = public_pem
        if not verify(key, d.unsigned_body(), d.signature.get("value", "")):
            return ValidationResult("invalid", f"invalid signature at chain hop {i + 1}")

    # 2. Attenuation: every child must be within its parent
    for parent, child in zip(chain, chain[1:]):
        violation = attenuation_violation(child.constraints, parent.constraints)
        if violation:
            return ValidationResult("invalid", violation)
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
    try:
        permissions, atoms = normalize(leaf.constraints)
    except ValueError as exc:
        return ValidationResult("invalid", f"malformed constraints: {exc}")

    perms = {(p.get("action"), p.get("system")) for p in permissions}
    want = (action_request.get("action"), action_request.get("system"))
    evaluated = [{"constraint": "permission", "pair": list(want), "satisfied": want in perms}]
    if want not in perms:
        return ValidationResult("invalid", "action/system not permitted by delegation",
                                constraints_evaluated=evaluated)

    # 4b. Every predicate used must be admitted by the Validation Profile.
    for atom in atoms:
        if atom["type"] not in profile.predicates:
            return ValidationResult(
                "invalid",
                f"predicate '{atom['type']}' not in profile {profile.uri or '(unnamed)'}",
                constraints_evaluated=evaluated,
            )

    env = envelope.build(action_request)
    view = {**env, "time": _iso(now)}
    obligations: list[dict[str, Any]] = []

    # 5. Predicates over attribute paths
    for atom in atoms:
        kind = atom["type"]
        path = atom["path"]

        if kind == "sum_max":
            try:
                observed = _dec(resolve(view, path))
            except (KeyError, IndexError, ValueError, TypeError):
                return ValidationResult("invalid", f"attribute {path} is missing",
                                        constraints_evaluated=evaluated)
            cap = _dec(atom["max"])
            key = atom.get("key") or action_request.get("budget_key") or "budget"
            period_start = action_request.get("period_start", "1970-01-01T00:00:00Z")
            if atom.get("period_seconds"):
                period_start = _iso(now - timedelta(seconds=int(atom["period_seconds"])))
            currency = None
            if path == "/attributes/amount":
                currency = env["attributes"].get("currency", "USD")
            spent = Decimal("0")
            if ledger is not None:
                spent = _dec(ledger.total_for(path, key, period_start, currency))
            remaining = cap - spent
            evaluated.append({"constraint": "sum_max", "path": path, "budget": key,
                              "cap": str(cap), "spent": str(spent),
                              "remaining": str(remaining),
                              "satisfied": observed <= remaining})
            if observed > remaining:
                return ValidationResult(
                    "invalid",
                    f"budget exhausted: {spent + observed} exceeds cap {cap} for {key}",
                    constraints_evaluated=evaluated,
                )
            continue

        if kind == "cosign_above":
            try:
                observed = _dec(resolve(view, path))
            except (KeyError, IndexError, ValueError, TypeError):
                return ValidationResult("invalid", f"attribute {path} is missing",
                                        constraints_evaluated=evaluated)
            threshold = _dec(atom["value"])
            approval_needed = observed > threshold
            evaluated.append({"constraint": "cosign_above", "path": path,
                              "bound": str(threshold), "observed": str(observed),
                              "satisfied": not approval_needed})
            if not approval_needed:
                continue
            ok, why = _check_approval(approval, leaf, action_request, atom, observed, now)
            evaluated.append({"constraint": "approval", "approval_id": (approval or {}).get("id"),
                              "satisfied": ok, "reason": why})
            if not ok:
                if approval is None:
                    return ValidationResult(
                        "indeterminate",
                        f"{path} {observed} exceeds approval threshold {threshold}; no approval supplied",
                        obligations=[{"type": "cosign_above", "path": path,
                                      "value": str(threshold), "observed": str(observed),
                                      "status": "required"}],
                        constraints_evaluated=evaluated,
                    )
                return ValidationResult(
                    "invalid",
                    f"approval does not satisfy the cosign_above obligation ({why})",
                    constraints_evaluated=evaluated,
                )
            obligations.append({"type": "cosign_above", "path": path,
                                "value": str(threshold), "observed": str(observed),
                                "status": "discharged", "approval_id": approval.get("id")})
            continue

        satisfied, observed, missing = evaluate(atom, view)
        evaluated.append({"constraint": kind, "path": path,
                          "bound": atom.get("value", atom.get("values", atom.get("start"))),
                          "observed": observed, "satisfied": satisfied})
        if not satisfied:
            return ValidationResult(
                "invalid",
                f"{path} {kind} predicate violated (observed {observed!r})",
                constraints_evaluated=evaluated,
            )

    return ValidationResult("valid", "within constraints",
                            obligations=obligations,
                            constraints_evaluated=evaluated)
