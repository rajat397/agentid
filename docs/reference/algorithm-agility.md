# Algorithm agility — preparing for post-quantum signatures

PQ cryptography **ships** as of Go 1.27: `crypto/mldsa` is in the standard
library (FIPS 204), integrated with `crypto/x509` and `crypto/tls`. This
satisfies the G13 revisit criterion that was previously unmet.

## What exists
- Every signed artifact carries `alg`: delegations, receipts, status tokens.
- `ValidationProfile.signature_algs` is an allowlist (default `["ES256"]`)
  and is part of the profile digest. Verifiers reject algorithms not listed.
- `Signer` supports multiple signatures via `DualSign(payload, signers)`.
  `Receipt.signature` remains the primary ES256 signature; `Receipt.signatures`
  carries the ML-DSA-65 signature. Delegations carry `Signatures` the same way.
- Default policy: dual-sign delegations and receipts. `ValidationProfile.pq_sign`
  (default `true`) allows a per-fleet opt-out; the flag is part of the profile
  digest. `VerifySignature(alg, keyMaterial, ...)` dispatches ES256 (PEM) and
  ML-DSA-65 (base64url raw FIPS 204 public key).

## Why PQ at all
ES256/RSA rely on factoring/discrete-log, which a sufficiently large quantum
computer can break with Shor's algorithm. Our evidence has a 20-year audit
horizon, so authenticity in 2046 matters. Payloads are hashes and opaque refs
— confidentiality ("harvest now, decrypt later") is not the concern.

## Measured cost (Go 1.27, 2,000 iterations, `tools/pqbench`)
| Measure | ES256 | ML-DSA-65 |
|---|---|---|
| Signature | 70 B | 3,309 B |
| Public key | 184 B | 1,952 B |
| Sign | 60 µs | 1.1 ms (~18×) |
| Verify | 105 µs | 320 µs (~3×) |
| Real receipt JSON | 1,069 B | 5,547 B (5.2×) |

Decision: the cost is accepted because audit authenticity is the product's
root claim and ~1 ms is small against an agent step. `pq_sign: false` exists
for latency-sensitive fleets. The built-in PQ key is process-ephemeral and
demo-grade; production callers must inject a stable `PQSigner` and publish its
public key material with their evidence bundle.

## Interop limit
ES256 primary verification is unchanged, so existing verifiers are unaffected.
Verifiers wanting PQ authenticity need an ML-DSA implementation (Go 1.27
stdlib, or equivalent in another language); the frozen Python oracle verifies
only the primary ES256 signature.

## Falsifier
An artifact signed with an algorithm outside the profile is accepted, or
adding a second signature requires changing the receipt format — then the
migration path is a claim, not a property. `tests/test_algorithm_agility.py`
pins both.
