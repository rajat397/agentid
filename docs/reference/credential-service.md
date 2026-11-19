# Credential service — signer boundary and rotation

Signing keys are held by the enforcement plane, never by the agent. Every
delegation hop and every receipt is signed through the same `Signer`
interface:

```
sign(payload) -> {alg: "ES256", kid, value}
public_key(kid) -> SPKI PEM
public_keys() -> {kid: PEM}     # published overlap set
```

## Implementations

- `DevSigner` — local PEM, emits a loud `RuntimeWarning`: NOT FOR PRODUCTION.
  Used only in demos and tests.
- `ExternalSigner` — takes a `sign_fn(canonical_bytes) -> raw_signature_bytes`
  and the provider's published public key. The adapter function wraps
  AWS KMS, GCP KMS, PKCS#11/HSM, or Vault; no private key material exists in
  this process and no provider SDK is imported by the library.
- `RotatingSigner` — current signer plus retired keys; signs with the
  current `kid`, verifies signatures under every retained `kid` for the
  published overlap window.

## Policy

Production rotation bound: **≤15 minutes** (kid changes, parent key pins are
reissued with it). Old receipts remain verifiable through the overlap set.
The key fingerprint in a delegation's `issuer.kid` is stable across signature
key rotation — it identifies the key pinned by the parent, not the KMS alias.

## Honest limits

- A receipt produced without a signer is **unsigned** but still hash-chained;
  `ledger.verify_chain()` accepts it and `receipt.signature is None`. The
  shipped demo and production path always supply a signer.
- Live KMS/HSM adapters are deployment code (a small callable), not shipped
  cloud credentials or SDK dependencies. The adapter contract is tested
  offline with an injected sign callable.
- The signer does not erase the need for delegation attenuation or receipt
  verification; it makes the authorship of each hop checkable.

## Falsifier

A receipt carrying a signature cannot be verified with the published key, or
a rotated-out key's signature fails inside the overlap window — then the
credential boundary is theater. `tests/test_signer_service.py` attacks both.
