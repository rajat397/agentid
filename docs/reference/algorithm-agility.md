# Algorithm agility — preparing for post-quantum signatures

No PQ cryptography ships in V1. This is deliberate: the format is ready, the
crypto is deferred until a stable, interoperable ML-DSA library is available
or a pilot/auditor requires it.

## What exists
- Every signed artifact carries `alg`: delegations, receipts, status tokens.
- `ValidationProfile.signature_algs` is an allowlist (default `["ES256"]`)
  and is part of the profile digest. Verifiers reject algorithms not listed.
- `Signer` supports multiple signatures via `dual_sign(payload, signers)`.
  `Receipt.signature` remains the primary signature; `Receipt.signatures`
  carries the additional ones. The artifact shape does not change.

## Why PQ at all
ES256/RSA rely on factoring/discrete-log, which a sufficiently large quantum
computer can break with Shor's algorithm. Our evidence has a 20-year audit
horizon, so authenticity in 2046 matters. Payloads are hashes and opaque refs
— confidentiality ("harvest now, decrypt later") is not the concern.

## Migration path (when triggered)
1. Implement a PQ `Signer` (ML-DSA-65 / FIPS 204) using a reviewed library;
   no private key material passes into the agent process.
2. Extend `signature_algs` in the profile; pin the new profile digest.
3. Dual-sign during the transition (ES256 + ML-DSA); verify both.
4. Document which algorithm is authoritative per profile version.

## Falsifier
An artifact signed with an algorithm outside the profile is accepted, or
adding a second signature requires changing the receipt format — then the
migration path is a claim, not a property. `tests/test_algorithm_agility.py`
pins both.
