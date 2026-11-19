# Anchor manager — cadence, retry and gap detection

A5 makes anchoring operational: heads are stamped at a customer-chosen cadence,
TSA failures are queued and retried, and missing anchors are detectable.

## Policy

`AnchorConfig{TSAURL, CAPEM, StrictCA, Cadence}`:

- `StrictCA` defaults to true. TLS uses system roots plus the optional customer
  CA bundle, TLS ≥ 1.2, and IPv4 dialing to avoid blackholed routes. There is no
  "disable verification" switch in the config. The TSA's **CMS** certificate
  chain still requires an external `openssl ts -verify` with `--ca`; our parser
  checks the request/response digest binding only (stated honestly).
- `Cadence{MaxReceipts, MaxInterval}` triggers after N new receipts or M
  elapsed time. `agentid anchor-watch --ledger … --tsa … --every N --out …`
  runs one observation pass.

`Observe` is called *after* receipt writes: a TSA failure never blocks an
action. Failed heads are queued (de-duplicated) and retried on the next pass.

## Auditor view

Anchors are included in the evidence bundle. `DetectAnchorGaps(anchors, ledger)`
reports anchors naming heads absent from the ledger, broken request/response
bindings, and a current chain head with no anchor — the last check is what
catches a dropped anchor in the bundle.

## Integration scenario (test-first)

`integration/anchoring_test.go` is the RED→GREEN feedback loop: cadence anchors
the first head, a TSA 500 leaves writes succeeding and queues the head, a retry
after recovery anchors the new head, removing an anchor is detected, and the
auditor bundle verifies. It failed RED before this implementation.

## Falsifier

Writes blocked by TSA failure, a queued head never retried, or a missing anchor
undetected — the scenario asserts all three.
