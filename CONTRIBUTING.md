# Contributing

## License

The open core is licensed under Apache-2.0. By contributing, you agree that your contribution is licensed under Apache-2.0. See [LICENSE](../LICENSE), [NOTICE](../NOTICE) and [reference/licensing.md](docs/reference/licensing.md).

Commercial modules, when shipped separately, are under [LICENSE-COMMERCIAL](../LICENSE-COMMERCIAL). Do not contribute commercial-layer code to this repository unless asked.

## Developer Certificate of Origin

All commits must be signed off:

```bash
git commit -s -m "fix: describe the change"
```

The sign-off line must be:

```text
Signed-off-by: Your Name <you@example.com>
```

By signing off, you certify the Developer Certificate of Origin at https://developercertificate.org/.

## Before you change anything that touches evidence

This repository's core asset is traceability. Every claim about a standard is checked against the normative text and recorded in `docs/reference/verification-log.md`.

Before you:

- change a document that makes a factual claim about a standard, or
- add a document that does so, or
- weaken or remove a test,

say so explicitly in your PR and justify it. "It sounded right" is not a justification. A source reference is.

## How to develop

Use Go 1.27 or newer.

```bash
go test ./...
go vet ./...
go run ./cmd/agentid demo
go run ./cmd/agentid evidence export --demo --out bundle.json
go run ./cmd/agentid evidence verify --file bundle.json
```

Playground changes:

```bash
cd playground
npm ci
npm test
npm run build
```

## What we need most right now

- Careful review of the standards mapping, especially anywhere we say "implemented" but of a form the source does not support.
- Conformance scenarios for schema drift after approval and revoked delegation after proposal.
- Threat model additions. We are certain there are threats we have not found.

## What we will not merge

- Changes that replace command-line evidence with adjectives.
- Changes that hide known limitations to make the project look finished.
- Contributions without DCO sign-off.
- Contributions under a license incompatible with Apache-2.0.
