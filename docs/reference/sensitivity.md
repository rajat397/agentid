# Data-sensitivity aggregation

A single-action check cannot prevent cumulative exposure. Sensitivity is an
ordinal ceiling and an aggregation key, expressed entirely with existing
predicates — no classifier verdict enters the decision.

## Tiers

`public(0) ⊑ internal(1) ⊑ confidential(2) ⊑ regulated(3)`. The action supplies
`sensitivity_tier`; the implementation derives `sensitivity_rank` in both the
validator and the action envelope. A caller-supplied rank that disagrees with
the tier is rejected; an unknown tier is rejected.

## Policy patterns

- **Ceiling**: `{"type":"max","path":"/attributes/sensitivity_rank","value":"2"}`
  — permits public/internal/confidential, denies regulated.
- **Cumulative exposure**:
  `{"type":"sum_max","path":"/attributes/rows","key":"regulated","max":"100"}`
  with actions carrying `budget_key: "regulated"` — caps the sum of rows for
  that tier across the delegation's window. Different tiers use different
  keys, so a regulated cap does not consume a confidential budget.

Both are digest-bound in the delegation and re-derivable from the receipt,
which records tier, derived rank and aggregation key.

## Falsifier

A sequence of under-cap reads within one tier exceeds the cumulative cap
without denial, or a forged rank / unknown tier passes — attacked in
`sensitivity_test.go`.

## Limits

Tier assignment is integration work; the core derives rank, not the label.
No DLP classifier participates in authorization.
