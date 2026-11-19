# Constraints — permissions plus predicates over action-envelope paths

Delegations constrain two things: **what** may be done, and **within which
bounds**. This document is normative for the implementation.

## The action envelope

Every action that crosses a trust boundary is describable canonically:

```json
{
  "action": "support.ticket.resolve",
  "system": "zendesk",
  "resource": {"type": "ticket", "id": "ticket_1001"},
  "attributes": {"region": "eu", "count": "5"},
  "nonce": "…"
}
```

`attributes` carries every non-structural field of the caller's request
(`amount`, `currency`, `region`, `count`, `personal_data_refs`, …). The
digest of the canonical envelope is the unit of approval, validation, and
receipt (`decision.envelope_digest`). Money is an attribute —
`/attributes/amount` — never the model.

## Permissions

Explicit `(action, system)` pairs. Two independent lists would imply a
Cartesian product of scopes (RFC 8693 §2.1.1) — the over-grant this model
exists to prevent.

## Predicates

Vocabulary (the IETF mandate draft's Table 1), each over an RFC 6901 pointer
into the envelope. A bare name is shorthand for `/attributes/<name>`.

| type | fields | meaning |
|---|---|---|
| `eq` | `path`, `value` | attribute equals value |
| `in` | `path`, `values[]` | attribute is in the set |
| `max` | `path`, `value` | numeric attribute ≤ value |
| `min` | `path`, `value` | numeric attribute ≥ value |
| `window` | `start`, `end`, [`path`] | action time (or attribute) within [start, end] |
| `sum_max` | `path`, `key`, `max`, [`period_seconds`] | rolling sum of a numeric attribute for `key` ≤ max |
| `cosign_above` | `path`, `value` | human approval required when attribute > value |

`sum_max` keys off the receipt attribute `budget_key` (configurable in code
at the adapter boundary). `cosign_above` produces a `cosign_above`
obligation when triggered; the approval must bind the action envelope
digest, carry an approver identity and a nonce, be unexpired, and name the
same delegation and action.

## Attenuation

A child delegation may never widen its parent:

- child permissions ⊆ parent permissions; child expiry ≤ parent expiry;
- for every parent predicate there must be a child predicate of the **same
  type and path** that is no looser (`in` ⊆, `max` ≤, `min` ≥, `eq` equal,
  `sum_max` same key and cap ≤, `cosign_above` threshold ≤, `window`
  inside);
- extra child predicates only narrow further.

Limitation, stated honestly: implication between different predicate types
(e.g. an `eq` that narrows an `in` set) is **not** inferred. Narrow with the
same predicate type.

## Legacy sugar

Previously issued grants used money-first keys. They still verify:

| legacy key | translated to |
|---|---|
| `max_amount {value}` | `max` on `/attributes/amount` |
| `requires_human_approval_above {value}` | `cosign_above` on `/attributes/amount` |
| `budget {key, value, period_seconds?}` | `sum_max` on `/attributes/amount` |

New grants should use `predicates`. Legacy keys are accepted for
verification, not recommended for issuance.

## Falsifier

An integrator cannot express a non-monetary action ("resolve ticket #123")
or a non-monetary constraint ("EU records only") without touching core
code — then "universal" is a claim, not a property. The suite
`tests/test_universal_actions.py` exists to keep that falsifier visible.
