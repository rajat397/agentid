# Revocation — IETF Token Status List (draft-21)

Wire format: `draft-ietf-oauth-status-list-21` (Proposed Standard intended;
not yet an RFC). Version pin lives in the Validation Profile digest.

## Format

Delegations may carry `status_list {idx, uri}`. The URI publishes a compact
JWS-shaped `statuslist+jwt`:

- header: `alg: ES256`, `typ: statuslist+jwt`, `kid` from our signer;
- claims: `sub` (URI), `iat`, `exp`, `ttl`, `status_list {bits: 2, lst}`, and
  our extension `status_count` (makes the bitset self-describing offline);
- `lst`: statuses packed LSB-first, ZLIB-compressed, base64url.

Status values: `0x00` VALID, `0x01` REVOKED, `0x02` SUSPENDED; `0x03`
reserved. The signature is a real ES256 JWS over the exact
`base64url(header).base64url(payload)` bytes, produced through the signer
interface — no private key in the agent process.

## Enforcement

The PEP caches the token with a freshness bound of
`min(ttl claim, max_status_age from the D26 registry decision)`. On breach,
unknown `kid`, bad signature, malformed token, or out-of-range index, it
**denies** and writes a receipt. A delegation with `status_list` and no
configured lookup is denied (fail closed). `0x01` and `0x02` stop the action;
`0x00` permits it.

## Limits

- One status list per fleet; the draft's aggregation URI extension is unused.
- Draft, not RFC: claim layout may change; version pin makes migration an
  auditable profile change, never a silent drift.
- `status_count` is ours, not IETF; verifiers must understand it (documented
  here and in the validator).

## Falsifier

A revoked status does not stop an action, or a stale/tampered token is
accepted — `tests/test_status_list.py` attacks both paths.
