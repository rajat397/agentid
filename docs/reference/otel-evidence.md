# OTel evidence layer — spans that corroborate receipts

A2 turns tracing from observability decoration into a second, independent
source of truth about what an agent did.

## Five moments

Every consequential action emits spans for `delegation.issue`, `validation`,
`obligation`, `downstream.call` and `receipt.persisted`. Each span carries a
`receipt_id`; each receipt carries `trace_id`/`span_id`/`traceparent` when a
trace context is supplied. The two artifacts corroborate each other — either
can be forged alone, but not both consistently.

## Propagation

`TraceContext` renders and parses W3C `traceparent`; `tracestate` carries
`agentid=<authority-hash>`, a digest of action, delegation and receipt. No
custom headers are introduced.

## Reconciliation

A caller-owned collector ingests spans (`POST /v1/traces`) and compares them
with the receipt ledger: missing span kinds, spans without receipts, receipts
without spans, and decision mismatches all raise `agentid.mismatch` metrics
(`GET /metrics`). The collector does not decide authorization; it detects
divergence between two evidence sources.

## PII and erasure

Subject attributes are pseudonymous by default (`subj_<sha256-prefix>`); raw
mode is explicit and documented in `BuildEvidenceSpans(..., rawPII=true)`.
`SpanDeletionHints(spans, subjectRef)` lists the trace/span/receipt ids to be
removed when a subject is erased.

## Commands

```
agentid otel-demo                                  # five spans + reconciliation from demo
agentid otel-serve --ledger receipts.jsonl --addr 127.0.0.1:4318
```

The semconv attribute names remain DEVELOPMENT/provisional; an upstream
OpenTelemetry proposal is an operator action, not a shipped claim.

## Integration scenario (test-first)

`integration/otel_evidence_test.go` went RED (no spans) → GREEN: five mutually
bound spans, W3C trace id, clean reconciliation, tamper detection, no raw PII
by default.

## Falsifier

A span lacks the receipt binding, a decision tamper reconciles clean, or raw
subject data appears by default — the scenario and unit tests attack all three.
