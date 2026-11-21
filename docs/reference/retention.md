# Retention — archive-before-prune and erasure tombstones

Q2/C14: minimization is an auditable action, not a silent cron.

## Policy

`RetentionPolicy{WindowMonths, ArchiveDir}` defaults to a 13-month window.
`ExportArchive(ledger, policy, at)` selects receipts issued before
`at - 13 months`, writes them as canonical JSONL into the customer-controlled
archive directory, computes a SHA-256 over the file, and appends an **ARCHIVE
receipt** to the same hash chain. Receipt bodies are never mutated in place;
anchors remain valid.

`VerifyArchive(path, receipt)` re-reads the file and checks digest, count and
receipt type using only the archive and the receipt — no issuer service.

## Erasure

`Tombstone(ledger, subjectRef, at)` appends a receipt naming the opaque subject
reference and the target receipt IDs. It does **not** rewrite old receipts:
changing a signed body would break the hash chain and every downstream anchor.
This is logical erasure over an append-only evidence chain; physical deletion
of derived data in customer systems is A1's erasure executor. `IsTombstoned`
lets verifiers treat those refs as erased for access decisions.

## CLI

```
agentid retention export --ledger receipts.jsonl --archive-dir /customer/archive [--at 2030-01-01T00:00:00Z]
```

## Integration scenario (test-first)

`integration/retention_test.go` went RED (no archive) → GREEN: archive written,
ARCHIVE receipt chain valid, tampering detected, tombstone recorded, original
receipts untouched.

## Falsifier

A receipt is silently pruned with no ARCHIVE receipt, the archive digest fails
to match, or a tombstone breaks the chain — the scenario and unit tests attack
all three.
