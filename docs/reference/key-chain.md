# Key chain — per-hop issuer authentication

A delegation chain is a chain of custody, not one key over a list of hops.

## Model

Each delegation carries:

- `issuer {id, kid}` — who signed it (the human for the root; the previous
  hop's actor for every child);
- `actor.verification_key` — the SPKI PEM of the key expected to sign the
  *next* hop, pinned inside the parent's signed body.

Verification walks the chain with the caller-pinned root key for hop 1, then
for every later hop uses the key pinned by its parent. The issuer `id` must
equal the parent's actor `id`, and the issuer `kid` must match the pinned
key's fingerprint. Any mismatch denies with a receipt.

This is fully offline: the decision path performs **no JWKS fetch, did:web
resolution or network call**. Key resolution reads a signed field in the
parent delegation. The endpoint documented in `docs/api/core-api.md` may
publish keys for auditors; it is not on the hot path.

## Rotation

Key rotation requires reissuing the parent grant with the new
`actor.verification_key`. A child signed by a rotated key is rejected at
creation time (`issuer key does not match parent's pinned actor …`), and
would be rejected by verification even if smuggled in. This trade-off is
deliberate: no network dependency in exchange for explicit reissuance.

## Depth

`ValidationProfile.max_chain_length` (example: 3) bounds verification and
revocation cost. Exceeding the bound denies with a receipt. The reference
suite exercises a 3-hop chain with three distinct keys
(`tests/test_issuer_chains.py`).

## Legacy fallback

Grants issued before per-hop issuer fields existed have no `issuer` and no
key pin; they verify against the single caller-supplied root key. A new-style
issuer cannot be attached to a legacy parent — the hop is denied. This keeps
old artifacts verifiable without opening a confused-deputy path.

## Falsifier

A child signed by a key other than the one pinned by its parent is accepted
— then key pinning is decoration. The suite attacks this directly.
