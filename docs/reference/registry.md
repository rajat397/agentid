# Registry — single-writer revocation state and status publication

D26 closes the loop between directory events and the PEP's status lookup.

## Boundary

The `registry` package exposes a small interface: `Register(subject, delegation,
idx)`, `Revoke(subject)`, `Entries()`. Writes are operator-side only; relying
parties never write. Implementations:

- `FileRegistry` (core, stdlib): append-only JSONL with a process-local writer
  mutex — the default for demos and offline verification.
- `optional/sqlite` (separate module, `modernc.org/sqlite`): single-writer SQL
  table with the same interface, for production-like deployments that want a
  durable registry without adding a dependency to the core.

`StatusPublisher` renders a registry snapshot into a signed `statuslist+jwt`
covering every registered index; revoked subjects become `0x01`.

## Runtime refresh

The MCP wrapper's status lookup is swap-compatible: `RefreshStatus(token, keys,
maxAge)` verifies the new token at its own issued time and atomically replaces
the PEP's lookup. A stale/malformed token is rejected without disturbing the
running one.

## Integration scenario (test-first)

`integration/offboarding_test.go` is the real-world feedback loop: an allowed
tool call, a SCIM deprovision, status publication, PEP refresh, then a denied
call with no downstream traffic. It failed RED before D26 because publication
was missing; it passes GREEN with the registry wired. This harness is the
template for subsequent features.

## Falsifier

A deprovisioned subject remains `0x00` after publication, the PEP keeps allowing
after refresh, or a revoked call reaches downstream — the scenario asserts all
three.
