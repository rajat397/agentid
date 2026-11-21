# Predicate typing and Type Profiles

A4 keeps exactly the seven mandate-draft predicates but makes their input
types explicit. A numeric predicate cannot be silently fed a string.

## Implicit rules (no Type Profile)

| predicate | required attribute type |
|---|---|
| `max`, `min`, `sum_max`, `cosign_above` | decimal string |
| `eq`, `in` | string |
| `window` | RFC 3339-ish timestamp (action time or attribute) |

A mismatch denies with `type error: <path> expects <type>, observed <type>`;
this is recorded in the receipt reason, so an auditor can re-derive it.

## Type Profile escape hatch

A Validation Profile may declare `type_profile`:

```
{"id":"tickets-v1",
 "attributes":{"/attributes/priority":"enum"},
 "enum_values":{"/attributes/priority":["low","high"]}}
```

An `in` predicate over `priority` now validates declared enum values. The
escape hatch covers **attribute types only** — it cannot invent predicates.
New predicates still require a spec/lattice change and new evaluator code;
this keeps the seven-predicate claim honest.

`type_profile` is part of the profile digest. Malformed declarations fail
validation before authorization.

## Integration scenario (test-first)

`integration/typing_test.go` went RED (no typed evaluation) → GREEN: a string
`rows` value was denied as a type error, and a Type Profile enum legitimized
`priority: high`.

## Falsifier

A numeric predicate accepts a string, an undeclared enum value passes, or a
malformed Type Profile is accepted — unit tests attack all three.
