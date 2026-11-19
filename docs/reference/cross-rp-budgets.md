# Cross-RP budgets — audience pinning and static partition

A `sum_max` key alone is not a budget: two relying parties using the same key
would either share a cap or double-count spend. Every stateful accumulation is
therefore keyed by **(key, audience)**.

## Semantics

- The action carries `aud` (the relying party); it is recorded in receipt
  attributes. Accumulation filters receipts by the same `aud`.
- A delegation may pin `constraints.aud`. When pinned, the action's `aud`
  must match or validation fails (`aud pinning`). Child delegations cannot
  change a pinned audience (attenuation check).
- When no audience is pinned, the action's `aud` still partitions the bucket;
  the legacy empty audience is its own partition. This keeps older grants
  verifiable without letting a new RP consume a legacy budget.

## Which options are in V1

- **O1 aud pinning** — implemented, structural for every stateful `sum_max`.
- **O3 static partition** — sanctioned and implemented: disjoint `key` values
  per fleet/RP give independent budgets.
- **O2 shared ledger across RPs** — deferred; gated on a Trust Framework with
  agreed accounting rules. Do not claim it.

## Falsifier

One RP's spend consumes another RP's budget, or a child delegation changes the
pinned audience — `audience_test.go` attacks both.
