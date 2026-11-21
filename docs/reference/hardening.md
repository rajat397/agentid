# Hardening pass — honest status

Trigger: operator asked whether work was deep and covered all cases. Answer:
scenarios test real paths, but "all cases" was false. This pass closed concrete
gaps and measured the rest.

## Fixed (each with a test)

- **Live status freshness** — PEP now checks wall-clock `iat`/`ttl`/`exp`
  (`VerifyStatusTokenLive`); archived bundles still verify at issued time.
  Replaying an old signed token into a running PEP is denied.
- **Signed approvals** — `SignApproval` binds the approval body under the
  approver's key; `require_signed_approvals` defaults to true in the real fleet
  profile (legacy profiles stay compatible for frozen-vector parity). Tampered
  approvals are denied.
- **MCP auth** — `/mcp` requires a bearer token compared in constant time; no
  token configured ⇒ HTTP 503 fail closed. `mcp-serve` requires
  `--auth-token-env`.
- **W3C round-trip** — fuzzing found `ParseTraceparent` discarded trace flags;
  `TraceContext.Flags` now preserves them.

## Measured

- Go core+integration tests pass; race detector clean.
- Fuzz targets: canonical JSON determinism, traceparent, TSTInfo parser,
  constraint normalization, authority hash. Fuzzing found one real bug above.
- Statement coverage across core+integration: **68.5%** (was 62.2%). Not 80%;
  remaining uncovered paths are mostly CLI variants and error branches.

## Honest residual gaps

- **Cross-language PQ**: the frozen Python oracle verifies ES256 primary only.
  It now prints `PARTIAL` when PQ signatures are present. `agentid verify-signed
  --artifact <file>` verifies all signatures (ES256 + ML-DSA-65) in Go 1.27+.
  A true second-language PQ verifier needs an ML-DSA implementation there.
- **No fuzzing of external vendor adapters**; connector auth/pagination are
  deployment adapters, not tested here.
- **CMS TSA chain-of-trust** still requires external `openssl ts -verify --ca`.
