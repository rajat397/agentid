# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security vulnerabilities in this project.

Report them privately to:

**super.agent.universe@gmail.com**

Include:

- a description of the issue and its impact,
- steps to reproduce (a minimal script is ideal),
- any relevant logs or evidence redacted of real third-party secrets.

You will receive an acknowledgement within 7 days. There is no bug bounty at
this stage, but you will receive credit for a confirmed, responsibly disclosed
report.

## What is in scope

- The `agentid` package, the tests, and the reference profile in `spec/`.
- The `docs/` analysis of third-party standards and specifications, where it
  misstates their requirements in a way that would mislead an implementer.

## What is not in scope

- Issues that are documented limitations of the open-core early-access product
  and are listed as such in `docs/architecture/overview.md`
  (e.g. "this is not tamper-proof", "injection prevention is out of layer").
- Third-party standards and their correctness. Those belong to their
  respective bodies (NIST, IETF, OTel). If you find an error in our
  *description* of a standard, that is in scope; if you find an error in the
  standard itself, the report is appreciated but we cannot fix it here.

## Threat model

The full threat model — trust zones, ten enumerated threats with mitigations,
residual risks stated plainly — is in `docs/security/threat-model.md`. Several
of its findings are deliberate, documented limitations, not undisclosed bugs.
