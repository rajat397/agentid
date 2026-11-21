# Erasure executor — deletion receipts and fail-closed execution

A1 turns the erasure plan into action. The executor talks to customer systems,
never claims success it did not observe, and receipts every completed deletion.

## Connector contract

`DownstreamConnector` has `System()`, `DeleteSubject(ref)` and
`VerifyAbsent(ref)`. Outcomes are explicit: `deleted`, `not_found` (idempotent
replay), `unreachable`, `forbidden`. `HTTPConnector` is the stdlib reference
binding to a minimal `DELETE /subjects/{ref}` + `GET /subjects/{ref}` API with
a bearer credential from deployment config or environment. Credentials never
enter receipts or bundles.

## Execution

`ExecuteErasure(ledger, requestID, subjectRef, connectors, at)` runs connectors
in order. A `deleted`/`not_found` outcome mints a chained deletion receipt
carrying the request id, system, outcome, opaque subject ref and the GDPR
30-day deadline. An `unreachable`/`forbidden` outcome halts with
`ERASURE_INCOMPLETE`; completed deletions before the failure are still
receipted (they really happened) but the run is not reported complete.
Retry is safe: `not_found` is success.

`VerifyErasure` re-queries every connector. Residue is reported as
`RESIDUE_FOUND: system`; transport failure as `VERIFY_FAILED`. No silent pass.

## CLI

```
agentid erasure-exec --subject cust_4471 --ledger receipts.jsonl \\
  --config connectors.json --request ers_1 --verify
```

`connectors.json` holds `{system, url, credential_env}` entries — no secrets.

## Integration scenario (test-first)

`integration/erasure_test.go` went RED (no receipts) → GREEN: connector failure
halted with `ERASURE_INCOMPLETE`, retry completed, both systems empty, deletion
receipts chained, verify clean.

## Falsifier

A failed connector is reported complete, a deletion receipt is minted without
connector action, or residue verifies clean — the scenario and unit tests attack
all three.
