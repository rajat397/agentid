"""Validation Profile — the artifact that makes decisions reproducible.

Identified by a URI and by the base64url-encoded SHA-256 digest of its bytes,
per draft-hulea-wimse-agent-mandate-01 §8. A receipt that names the profile
digest can be re-derived by any party holding the same inputs.
"""

import json
from dataclasses import dataclass
from typing import Any

from .crypto import b64url_digest_sha256, canonical_json


@dataclass(frozen=True)
class ValidationProfile:
    """Loaded, verified profile. `digest` is the content-address."""

    uri: str
    iss: str
    max_clock_skew: int
    max_pop_window: int
    max_token_lifetime: int
    max_status_age: int
    max_chain_length: int
    predicates: tuple[str, ...]
    status_values: dict[str, str]
    signature_algs: tuple[str, ...] = ("ES256",)

    @property
    def digest(self) -> str:
        return b64url_digest_sha256(canonical_json(self._document()))

    def _document(self) -> dict[str, Any]:
        return {
            "iss": self.iss,
            "max_chain_length": self.max_chain_length,
            "max_clock_skew": self.max_clock_skew,
            "max_pop_window": self.max_pop_window,
            "max_status_age": self.max_status_age,
            "max_token_lifetime": self.max_token_lifetime,
            "predicates": list(self.predicates),
            "status_values": dict(self.status_values),
            "signature_algs": list(self.signature_algs),
        }

    def document(self) -> dict[str, Any]:
        doc = self._document()
        doc["digest"] = self.digest
        return doc

    @classmethod
    def load(cls, path: str) -> "ValidationProfile":
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ValidationProfile":
        required = [
            "iss",
            "max_clock_skew",
            "max_pop_window",
            "max_token_lifetime",
            "max_status_age",
            "max_chain_length",
            "predicates",
        ]
        missing = [k for k in required if k not in raw]
        if missing:
            raise ValueError(f"profile missing required keys: {missing}")
        if not isinstance(raw["predicates"], list) or not raw["predicates"]:
            raise ValueError("profile.predicates must be a non-empty list")
        return cls(
            uri=raw.get("uri", ""),
            iss=raw["iss"],
            max_clock_skew=int(raw["max_clock_skew"]),
            max_pop_window=int(raw["max_pop_window"]),
            max_token_lifetime=int(raw["max_token_lifetime"]),
            max_status_age=int(raw["max_status_age"]),
            max_chain_length=int(raw["max_chain_length"]),
            predicates=tuple(raw["predicates"]),
            status_values=dict(raw.get("status_values", {})),
            signature_algs=tuple(raw.get("signature_algs", ["ES256"])),
        )

    @staticmethod
    def example() -> "ValidationProfile":
        return ValidationProfile(
            uri="https://example.invalid/profiles/agentic-v1.json",
            iss="example-rp",
            max_clock_skew=30,
            max_pop_window=300,
            max_token_lifetime=900,
            max_status_age=60,
            max_chain_length=3,
            predicates=("eq", "in", "max", "min", "window", "sum_max", "cosign_above"),
            status_values={"0x02": "suspended"},
        )
