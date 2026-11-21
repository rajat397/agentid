# Intent compiler — constrained drafts, human-activated authority

B10 turns natural language into a *proposal*. It never invents authority.

## Bounded compilation

`CompileIntent(text)` matches a fixed pattern set: actor, action/system,
monetary cap, expiry, optional approval threshold and optional EU region.
Anything unrecognized is returned in `Unmatched`; the compiler does not guess.
The result is a `Draft` delegation plus a `Digest` over text, plan and draft.

## Human gate

`ActivateIntent(compilation, approval, signer)` requires:

1. a cryptographically signed approval (existing `SignApproval` contract);
2. `approves_compilation_digest` equal to this exact compilation digest;
3. zero unmatched clauses.

Only then is a real delegation signed and marked live. Drafts are rejected by
the validator with `delegation is a draft; human review required`, so a draft
can never authorize a tool call even if it reaches a PEP.

This is deliberately *not* an LLM call: a model may propose wording, but the
compiler's pattern set and the human's signature are the authority boundary.

## Integration scenario (test-first)

`integration/intent_test.go` went RED (no compilation) → GREEN: the draft was
rejected, human review activated the exact digest, and ambiguous intent left
unmatched clauses.

## Falsifier

A draft authorizes an action, an approval for a different digest activates a
compilation, or ambiguous intent silently produces a plan — unit and
integration tests attack all three.
