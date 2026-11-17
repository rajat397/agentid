# Contributing

## Before you change anything that touches evidence

This repository's core asset is its traceability: every claim about a standard
is checked against the normative text, and the check is recorded in
`docs/reference/verification-log.md`.

So before you:

- change a document that makes a factual claim about a standard, or
- add a document that does so, or
- weaken or remove one of the tests,

say so explicitly in your PR and justify it. "It sounded right" is not a
justification. A page reference is.

## How to develop

```bash
git clone <fork-url> && cd agentid
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest                    # must stay green
agentid demo              # must stay green
```

## What we need most right now

- A careful review of the standards mapping, especially anywhere we say
  "implemented" but of a form the source does not actually support.
- Erasure flow tests against realistic downstream systems.
- Threat model additions — we are certain there are threats we have not found.

## What we will not merge

- Changes that replace command-line evidence with adjectives.
- Changes that hide known limitations to make the project look finished.
- Contributions under a license incompatible with MIT.
