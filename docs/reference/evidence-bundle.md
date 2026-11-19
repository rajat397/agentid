# Evidence bundle — portable, self-verifying archive (B7)

The archive is a **file format**, not a service we host. An auditor must be
able to verify every artifact without contacting us or any network.

## Format (`agentid-evidence/v1`)

Canonical JSON with these sections:

| section | contents |
|---|---|
| `receipts` | full receipt bodies, hash-chained, ES256 primary + ML-DSA-65 additive signatures |
| `delegations` | every referenced authority hop with signatures and key registry |
| `profile` | the Validation Profile document (including `pq_sign`) |
| `anchors` | RFC 3161 anchor records (head hash, request/response, genTime) |
| `status_tokens` | signed `statuslist+jwt` tokens |
| `signer_keys` | public key material: ES256 PEM and ML-DSA-65 base64url raw keys |
| `manifest` | SHA-256 of the canonical body, artifact counts, profile digest |

Every receipt carries `decision.profile_digest`, so a bundle that swaps the
profile is caught by two independent checks.

## Offline verification gates

`agentid evidence verify --file bundle.json` checks, with no network:

1. manifest digest and profile digest (bundle + each receipt);
2. receipt hash chain and **all** signatures, using only bundled keys;
3. delegation signatures at every hop and receipt→delegation references;
4. anchor request/response binding at any recorded head (historical heads
   need not equal the current chain tip);
5. status-token signatures and status decoding, evaluated at the token's
   recorded `iat` (no wall-clock freshness — archives stay verifiable years
   later);
6. key coverage — every signature `kid` must resolve inside the bundle.

## Custody adapters

`EvidenceStore`: `LocalStore` (customer directory) and `PresignedURLStore`
(S3/GCS via a customer-supplied presigned PUT URL). Object-lock / WORM
retention is configured at the storage provider; the library never claims to
enforce it. No hosted archive: we remain tooling, not custodian.

## Limits

- The frozen Python oracle verifies only the primary ES256 signature of
  Go-produced artifacts; PQ verification needs Go 1.27 stdlib or equivalent.
- Bundles are snapshots; incremental archival is the customer's cadence
  decision (see Q2 retention and `ARCHIVE` receipts).

## Falsifier

An auditor needs our service to verify a bundle, or a referenced artifact/key
is missing and verification still passes — `tests/evidence_test.go` attacks
tampered receipts, manifests, missing keys/delegations and malformed tokens.
