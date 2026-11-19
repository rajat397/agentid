"""Canonical action envelope — the unit of approval, validation and receipt.

Every action that crosses a trust boundary is describable the same way:
the verb, the system, the resource, and the attributes the verb operates on.
Money is an attribute, not the model.

    envelope = {
        "action":   "support.ticket.resolve",
        "system":   "zendesk",
        "resource": {"type": "ticket", "id": "ticket_1001"},
        "attributes": {...},
        "nonce":    "..."
    }

The digest of the canonical envelope binds approvals to the exact act.
"""

from typing import Any

from .crypto import canonical_json, digest_sha256

# Keys that are structure, not action attributes.
_RESERVED = {"action", "system", "resource_type", "resource_id", "nonce", "external_ref"}


def build(action_request: dict[str, Any]) -> dict[str, Any]:
    """Project a flat action request into the canonical envelope shape."""
    if "action" not in action_request or "system" not in action_request:
        raise ValueError("action envelope requires both 'action' and 'system'")
    return {
        "action": action_request["action"],
        "system": action_request["system"],
        "resource": {
            "type": action_request.get("resource_type"),
            "id": action_request.get("resource_id"),
        },
        "attributes": {
            k: v for k, v in action_request.items() if k not in _RESERVED
        },
        "nonce": action_request.get("nonce"),
    }


def digest(action_request: dict[str, Any]) -> str:
    """Content-address of the action envelope — what approvals bind to."""
    return digest_sha256(canonical_json(build(action_request)))
