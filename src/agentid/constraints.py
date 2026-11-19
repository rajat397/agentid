"""Constraint model — permissions plus predicates over action-envelope paths.

A delegation constrains *what* may be done (explicit action/system pairs) and
*within which bounds* (predicates over attribute paths, RFC 6901 pointers).
The predicate vocabulary is the IETF mandate draft's Table 1, generalized:
eq, in, max, min, window, sum_max, cosign_above — each over any attribute.

Money is one instance: `/attributes/amount`. The legacy money-first constraint
keys (`max_amount`, `requires_human_approval_above`, `budget`) are accepted as
sugar and translated here, so previously issued delegations keep verifying.
"""

from decimal import Decimal, InvalidOperation
from typing import Any

PREDICATE_TYPES = ("eq", "in", "max", "min", "window", "sum_max", "cosign_above")

_NUMERIC_DEFAULT_PATH = "/attributes/amount"


def _dec(value: Any) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ValueError(f"predicate observed value is not numeric: {value!r}")
    try:
        return Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"predicate observed value is not numeric: {value!r}") from exc


def resolve(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON Pointer. A bare name means /attributes/<name>."""
    if not pointer.startswith("/"):
        pointer = f"/attributes/{pointer}"
    current = document
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(pointer)
    return current


def _atom(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict) or "type" not in raw:
        raise ValueError("predicate must be an object with a type")
    atom = dict(raw)
    kind = atom["type"]
    if kind not in PREDICATE_TYPES:
        raise ValueError(f"unknown predicate type: {kind!r}")
    if kind in ("eq", "max", "min", "sum_max", "cosign_above"):
        if "path" not in atom:
            atom["path"] = _NUMERIC_DEFAULT_PATH
        if not str(atom["path"]).startswith("/"):
            atom["path"] = f"/attributes/{atom['path']}"
    if kind == "in":
        if "path" not in atom or not isinstance(atom.get("values"), list) or not atom["values"]:
            raise ValueError("in predicate needs a path and a non-empty values list")
        atom["values"] = list(atom["values"])
    elif kind in ("eq", "cosign_above"):
        if "value" not in atom:
            raise ValueError(f"{kind} predicate needs a value")
        atom["value"] = str(atom["value"])
    elif kind in ("max", "min"):
        if "value" not in atom:
            raise ValueError(f"{kind} predicate needs a value")
        _dec(atom["value"])
        atom["value"] = str(atom["value"])
    elif kind == "sum_max":
        if "max" not in atom:
            raise ValueError("sum_max predicate needs a max")
        _dec(atom["max"])
        atom["max"] = str(atom["max"])
        atom["key"] = str(atom.get("key", "budget"))
        if "period_seconds" in atom:
            atom["period_seconds"] = int(atom["period_seconds"])
    elif kind == "window":
        if "start" not in atom or "end" not in atom:
            raise ValueError("window predicate needs start and end")
        atom.setdefault("path", "/time")
    return atom


def normalize(constraints: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return (permissions, predicate atoms) for a constraints object.

    Legacy money-first keys are translated into the same atom vocabulary.
    """
    if not isinstance(constraints, dict):
        raise ValueError("constraints must be an object")
    permissions = list(constraints.get("permissions", []))
    atoms: list[dict[str, Any]] = []

    if "max_amount" in constraints:
        atoms.append({"type": "max", "path": _NUMERIC_DEFAULT_PATH,
                      "value": str(constraints["max_amount"]["value"]),
                      "legacy": "max_amount"})
    if "requires_human_approval_above" in constraints:
        atoms.append({"type": "cosign_above", "path": _NUMERIC_DEFAULT_PATH,
                      "value": str(constraints["requires_human_approval_above"]["value"]),
                      "legacy": "requires_human_approval_above"})
    if "budget" in constraints:
        budget = constraints["budget"]
        atom = {"type": "sum_max", "path": _NUMERIC_DEFAULT_PATH,
                "key": str(budget.get("key", "budget")),
                "max": str(budget["value"]),
                "legacy": "budget"}
        if "period_seconds" in budget:
            atom["period_seconds"] = int(budget["period_seconds"])
        atoms.append(atom)

    for raw in constraints.get("predicates", []):
        atoms.append(_atom(raw))
    return permissions, atoms


def evaluate(atom: dict[str, Any], view: dict[str, Any]) -> tuple[bool, Any, str | None]:
    """Return (satisfied, observed, failure_reason) for one predicate atom."""
    kind = atom["type"]
    path = atom["path"]
    try:
        observed = resolve(view, path)
    except (KeyError, IndexError, ValueError, TypeError):
        return False, None, f"attribute {path} is missing"

    if kind == "eq":
        return str(observed) == atom["value"], observed, None
    if kind == "in":
        return str(observed) in {str(v) for v in atom["values"]}, observed, None
    if kind == "max":
        return _dec(observed) <= _dec(atom["value"]), observed, None
    if kind == "min":
        return _dec(observed) >= _dec(atom["value"]), observed, None
    if kind == "window":
        when = str(observed)
        return atom["start"] <= when <= atom["end"], observed, None
    # sum_max and cosign_above are completed by the caller (ledger/approval).
    return True, observed, None


def _no_looser(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    kind = parent["type"]
    if kind == "eq":
        return child["value"] == parent["value"]
    if kind == "in":
        return {str(v) for v in child["values"]} <= {str(v) for v in parent["values"]}
    if kind == "max":
        return _dec(child["value"]) <= _dec(parent["value"])
    if kind == "min":
        return _dec(child["value"]) >= _dec(parent["value"])
    if kind == "sum_max":
        return (child.get("key") == parent.get("key")
                and _dec(child["max"]) <= _dec(parent["max"]))
    if kind == "cosign_above":
        return _dec(child["value"]) <= _dec(parent["value"])
    if kind == "window":
        return child["start"] >= parent["start"] and child["end"] <= parent["end"]
    return False


def attenuation_violation(child: dict[str, Any], parent: dict[str, Any]) -> str | None:
    """Return a violation message if `child` widens `parent`, else None.

    Every parent predicate must be matched (same type and path) by a child
    predicate that is no looser. Extra child predicates only narrow further.
    Implication between different predicate types (eq narrowing an in set) is
    not inferred — use the same predicate type to narrow.
    """
    try:
        c_perms, c_atoms = normalize(child)
        p_perms, p_atoms = normalize(parent)
    except ValueError as exc:
        return f"attenuation violated: malformed constraints ({exc})"

    c_pairs = {(p.get("action"), p.get("system")) for p in c_perms}
    p_pairs = {(p.get("action"), p.get("system")) for p in p_perms}
    if not c_pairs <= p_pairs:
        return "attenuation violated: child permissions exceed parent"

    for parent_atom in p_atoms:
        candidates = [a for a in c_atoms
                      if a["type"] == parent_atom["type"] and a["path"] == parent_atom["path"]]
        if not candidates:
            return (f"attenuation violated: child drops parent "
                    f"{parent_atom['type']} predicate on {parent_atom['path']}")
        if not any(_no_looser(c, parent_atom) for c in candidates):
            return (f"attenuation violated: child {parent_atom['type']} on "
                    f"{parent_atom['path']} is looser than parent")
    return None
