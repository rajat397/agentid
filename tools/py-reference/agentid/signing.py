"""Credential-service signer boundary.

The agent never sees a private key. All signing goes through `Signer`:
`DevSigner` for labeled local development, `ExternalSigner` for KMS/HSM
adapters (a sign callable plus the published public key — no key material in
this process), and `RotatingSigner` for the published overlap window.

Rotation bound: 15 minutes in production policy (see docs); rotation changes
the signature `kid`, never the issuer's key fingerprint pinned in its parent.
"""

import warnings
from typing import Any, Callable

from .crypto import canonical_json, key_fingerprint, sign_raw


class Signer:
    """Minimal contract: current kid, sign, resolve a kid to its public key."""

    def sign(self, payload: dict[str, Any]) -> dict[str, str]:
        return {"alg": "ES256", "kid": self.kid,
                "value": self.sign_raw(canonical_json(payload))}

    def sign_raw(self, data: bytes) -> str:
        raise NotImplementedError

    def public_key(self, kid: str) -> str:
        raise NotImplementedError

    def public_keys(self) -> dict[str, str]:
        raise NotImplementedError

    @property
    def kid(self) -> str:
        raise NotImplementedError


class DevSigner(Signer):
    """Local PEM signer. Loudly labeled as not for production."""

    def __init__(self, private_pem: str, public_pem: str,
                 kid: str | None = None, warn: bool = True) -> None:
        if warn:
            warnings.warn(
                "DevSigner uses a local private key — NOT FOR PRODUCTION; "
                "use ExternalSigner with a KMS/HSM adapter.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._private_pem = private_pem
        self._public_pem = public_pem
        self._kid = kid or key_fingerprint(public_pem)

    @property
    def kid(self) -> str:
        return self._kid

    def sign_raw(self, data: bytes) -> str:
        return sign_raw(self._private_pem, data)

    def public_key(self, kid: str) -> str:
        if kid != self._kid:
            raise KeyError(kid)
        return self._public_pem

    def public_keys(self) -> dict[str, str]:
        return {self._kid: self._public_pem}


class ExternalSigner(Signer):
    """KMS/HSM adapter: `sign_fn(canonical_bytes) -> raw_signature_bytes`.

    The private key stays in the provider; this object holds only the public
    key and a callable. The adapter function is supplied by the deployment
    (for example a boto3 `sign` call), so no provider SDK is imported here.
    """

    def __init__(self, kid: str, public_pem: str,
                 sign_fn: Callable[[bytes], bytes]) -> None:
        self._kid = kid
        self._public_pem = public_pem
        self._sign_fn = sign_fn

    @property
    def kid(self) -> str:
        return self._kid

    def sign_raw(self, data: bytes) -> str:
        from .crypto import b64url
        return b64url(self._sign_fn(data))

    def public_key(self, kid: str) -> str:
        if kid != self._kid:
            raise KeyError(kid)
        return self._public_pem

    def public_keys(self) -> dict[str, str]:
        return {self._kid: self._public_pem}


class RotatingSigner(Signer):
    """Current signer plus retired keys, verifiable for the overlap window."""

    def __init__(self, signers: list[Signer]) -> None:
        if not signers:
            raise ValueError("RotatingSigner needs at least one signer")
        self._signers = list(signers)

    @property
    def kid(self) -> str:
        return self._signers[0].kid

    def sign(self, payload: dict[str, Any]) -> dict[str, str]:
        signature = self._signers[0].sign(payload)
        return {**signature, "kid": self.kid}

    def sign_raw(self, data: bytes) -> str:
        return self._signers[0].sign_raw(data)

    def public_key(self, kid: str) -> str:
        for signer in self._signers:
            if signer.kid == kid:
                return signer.public_key(kid)
        raise KeyError(kid)

    def public_keys(self) -> dict[str, str]:
        keys: dict[str, str] = {}
        for signer in self._signers:
            keys.update(signer.public_keys())
        return keys


def dual_sign(payload: dict[str, Any], signers: list[Signer]) -> list[dict[str, str]]:
    """Sign one payload under several algorithms (migration hedge).

    No PQ algorithm is implemented here; a PQ Signer may be supplied by a
    deployment once a stable library exists. The artifact shape is unchanged:
    the primary signature stays in `signature`, others in `signatures`.
    """
    return [signer.sign(payload) for signer in signers]
