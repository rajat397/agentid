# Provenance taint — injection-aware authorization

The PEP sees the action, not the conversation that produced it. This layer
makes the *source* of an action an explicit, auditable input to authorization
without importing a probabilistic classifier into the decision path.

## Lattice

`provenance ∈ {trusted, untrusted}`. `JoinProvenance` is conservative: one
untrusted input taints the result; no inputs means untrusted.
`ProvenanceTracker.Observe` joins sources across tool results and prompts; its
current value is written to the action envelope as `attributes.provenance`.

## Policy

`ValidationProfile.require_trusted_provenance` (default `false` until an
integration supplies provenance) enables the gate:

- `provenance == trusted` → normal predicate evaluation;
- otherwise → `indeterminate` with obligation `cosign_untrusted`. Discharging
  it requires an approval that binds the **action envelope digest**, carries
  an approver + nonce, and explicitly sets `acknowledges_untrusted: true`.

A hard denial is expressible with the existing Table 1 grammar: an `eq`
predicate on `/attributes/provenance` with value `trusted`. No new predicate
types were added for injection handling.

## Evidence and falsifier

The receipt records the observed provenance in its constraints evaluation and
the discharged obligation, so a reviewer can re-derive why a gate fired. A
classifier may *set* the taint label upstream, but it never authorizes: the
decision remains deterministic and re-derivable from the receipt.

Falsifier: an action derived from untrusted content passes a high-risk gate
with no approval, or the taint decision cannot be reconstructed from the
receipt — `provenance_test.go` attacks both.

## Limits

The integration must supply provenance; the core cannot infer it from an
arbitrary prompt. Continuous re-evaluation after delegation issuance is not
in V1.
