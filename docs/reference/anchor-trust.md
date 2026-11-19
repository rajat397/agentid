# Anchor flavors and their trust assumptions

No flavor puts our infrastructure in the verification path. The customer
selects one at install time; the choice is part of the evidence bundle.

## `rfc3161` (default)

The customer selects a TSA URL and CA bundle; strict TLS uses system roots plus
that CA. The TSA sees the 32-byte chain-head hash, never receipt contents. It
cannot forge our receipts; it *can* lie about `genTime`, which is why the
customer chooses a TSA they trust and pins its CA. Full CMS certificate-chain
verification is an external `openssl ts -verify --ca` operation; our verifier
checks the request/response digest binding only.

## `bucket`

The customer writes a signed head-stamp `{head_seq, head_hash, gen_time,
signer_kid, alg, signature}` into storage they control (local dir, S3/GCS via
their own tooling). The trust root is the customer's key: an auditor verifies
the stamp offline with that public key and compares `head_hash` to the ledger
head. There is no third party and no network requirement. The trade-off: if the
customer loses the key or the bucket, the anchor is gone — key custody is
theirs.

## `transparency-log`

Stub only. `NewAnchorManager` fails closed if this flavor is selected in V1.
No public log is contacted.

## Choosing

External auditor who needs an independent clock → `rfc3161`. Air-gapped or
sovereign deployment → `bucket`. Do not claim two-of-three anchoring: V1
supports exactly one flavor per deployment.
