# Pipeline stages — capability ceilings for agent workflows

Action names are not stages. A "read" tool can be mislabeled; a stage ceiling
is a signed property of the delegation, enforced independently of the verb.

## Lattice

`plan ⊑ read ⊑ write ⊑ side_effect`. A delegation constraint `stage: "read"`
permits `plan` and `read` actions but denies `write` and `side_effect`. A
child delegation cannot raise the ceiling; it can only narrow it. The stage
lives in the canonical action envelope and is recorded in the receipt's
resource, so incident review can re-derive which phase produced an action.

The profile may additionally declare `stage_allowlist` (e.g. only `plan` and
`read` for a whole fleet); it is part of the profile digest. When a ceiling or
allowlist is present, an action with a missing or unknown stage is denied —
fail closed.

## Compatibility

Action requests without a stage keep the exact previous envelope digest: the
`stage` key is only emitted when present. Existing grants without a stage
constraint are unrestricted, as before.

## Gap found while implementing

`ProfileFromMap` normalized a JSON `null` stage allowlist into an empty slice,
changing the profile digest between bundle creation and verification. Fixed by
preserving nil for absent lists; the evidence-bundle gate caught it.

## Falsifier

A grant scoped to `plan|read` produces an accepted `side_effect` action, a
child raises its parent's ceiling, or the stage cannot be read from the receipt
— `stage_test.go` attacks all three.
