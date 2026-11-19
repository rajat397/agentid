"""agentid — identity, guardrails, reliability and traceability for software agents.

A minimal reference implementation. It backs three claims with executable
tests: a leaked credential can be revoked and denied with a receipt; an
incident can be reconstructed from receipts alone; and an erasure request can
be traced to every agent action that touched the subject's data.

Scope: this is not a production control plane and is not offered as one.
"""

__version__ = "0.1.0"

from .crypto import canonical_json, digest_sha256, sign, verify, b64url
from .delegation import Delegation, create_delegation
from .receipt import Receipt
from .ledger import Ledger
from .validator import ValidationResult, validate
from .profile import ValidationProfile
from .erasure import build_erasure_plan, ErasurePlan

__all__ = [
    "canonical_json",
    "digest_sha256",
    "sign",
    "verify",
    "b64url",
    "Delegation",
    "create_delegation",
    "Receipt",
    "Ledger",
    "ValidationResult",
    "validate",
    "ValidationProfile",
    "build_erasure_plan",
    "ErasurePlan",
]
