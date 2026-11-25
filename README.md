# agentid

**An agent acted. Prove who authorized it.**

> Status: experimental reference implementation. Not production-ready, not certified, not for sale. All rights reserved.

`agentid` makes a consequential agent action re-derivable instead of merely logged. It binds a signed, narrow envelope to a tool call, gates execution at a credential-holding enforcement point, and emits receipts an auditor can verify offline without trusting a hosted service.

Go 1.27 standard-library core. No external Go modules. Dual-signed by default with ES256 plus ML-DSA-65.

```bash
go test ./...
go run ./cmd/agentid demo
go run ./cmd/agentid evidence export --demo --out bundle.json
go run ./cmd/agentid evidence verify --file bundle.json
```

## Why?

Agents are a new kind of principal. They act on behalf of someone, inherit limited authority, call tools with side effects, and leave records that are normally just their own logs. `agentid` gives that problem four small primitives:

| You want to... | agentid gives you |
|---|---|
| Decide an action from canonical facts | `agentid` action envelope: `action`, `system`, `resource`, typed attributes |
| Keep downstream credentials away from the agent | `agentid wrap` MCP stdio proxy and the MCP wrapper PEP |
| Bound what the agent may do | delegation chains, seven typed predicates, budgets, stage ceilings, provenance taint |
| Prove a decision months later | signed, hash-chained receipts, status lists, anchors, portable evidence bundles |
| Revoke authority when a person leaves | SCIM ingestion, signed status lists, control-plane bundles that fail closed when stale |
| Answer erasure and retention questions | erasure executor, deletion receipts, archive-before-prune retention |
| Wire an existing harness | 8 adapters and one CLI decision service |

Everything is expressed as a signed profile plus command-line workflows. There is no hosted verification path.

## Quick start

### 1. Install Go 1.27

Go 1.27 is required for `crypto/mldsa` in the standard library. No external Go modules are needed.

```bash
go version
```

### 2. Run the lifecycle

```bash
git clone https://github.com/rajat397/agentid.git
cd agentid
go test ./...
go run ./cmd/agentid demo
```

The demo runs the same code the tests exercise: a human grants authority, an over-cap action is denied with a receipt, an allowed action is receipted, four audit questions are answered from receipts alone, and a tampered receipt fails verification.

### 3. Export and verify evidence

```bash
go run ./cmd/agentid evidence export --demo --out bundle.json
go run ./cmd/agentid evidence verify --file bundle.json
go run ./cmd/agentid verify-signed --artifact /path/to/cross-artifact.json
```

The bundle contains receipts, chains, the validation profile, status tokens, anchors and signer keys. The verifier checks the math, not our service.

### 4. Wrap a live MCP path

```bash
go run ./cmd/agentid wrap --config spec/validation-profile.example.json -- <your-mcp-server>
```

The agent sees ordinary JSON-RPC tools. The wrapper holds downstream credentials, maps `tools/call` into action envelopes, validates before execution, and receipts every decision.

## CLI usage

```bash
# Inspect and verify
go run ./cmd/agentid profile
go run ./cmd/agentid evidence export --demo --out bundle.json
go run ./cmd/agentid evidence verify --file bundle.json
go run ./cmd/agentid verify-signed --artifact <file>

# Lifecycle and operations
go run ./cmd/agentid demo
go run ./cmd/agentid erasure cust_4471 --demo
go run ./cmd/agentid anchor --ledger <receipts.jsonl> [--tsa URL]
go run ./cmd/agentid serve --bundle bundle.json --addr 127.0.0.1:8080

# Adapters
go run ./cmd/agentid wrap --config <profile> -- <mcp-server>
go run ./cmd/agentid claude-hook
```

## Adapters

| Harness | Entry point | Reference |
|---|---|---|
| MCP stdio | `agentid wrap` | [mcp-transport-adapter.md](docs/reference/mcp-transport-adapter.md) |
| Claude Code | `PreToolUse` hook | [claude-code-hook.md](docs/reference/claude-code-hook.md) |
| LangChain / LangGraph | one middleware line | [langchain-adapter.md](docs/reference/langchain-adapter.md) |
| Google ADK | `before_tool_callback` | [adk-adapter.md](docs/reference/adk-adapter.md) |
| CrewAI | `PRE_TOOL_CALL` hook | [crewai-adapter.md](docs/reference/crewai-adapter.md) |
| Semantic Kernel / AutoGen | filter + intervention handler | [sk-autogen-adapter.md](docs/reference/sk-autogen-adapter.md) |
| OpenAI Agents SDK | tool-input guardrail | [openai-adapter.md](docs/reference/openai-adapter.md) |
| n8n | importable gate sub-workflow | [n8n-adapter.md](docs/reference/n8n-adapter.md) |

## Docs

| Guide | Read it to... |
|---|---|
| [architecture/overview.md](docs/architecture/overview.md) | Understand components, constraints, flows and open questions |
| [reference/standards-matrix.md](docs/reference/standards-matrix.md) | Check every NIST/IETF claim against the normative text |
| [reference/constraints.md](docs/reference/constraints.md) | Write action envelopes, predicates and stage ceilings |
| [reference/mcp-wrapper.md](docs/reference/mcp-wrapper.md) | Understand where credentials are held and how denial is returned |
| [reference/policy-combining.md](docs/reference/policy-combining.md) | See deny-overrides, implicit deny and obligation union |
| [reference/evidence-bundle.md](docs/reference/evidence-bundle.md) | Verify a bundle offline |
| [reference/verification-api.md](docs/reference/verification-api.md) | Mount `/receipts/verify` and `/v1/keys` for third parties |
| [reference/control-plane.md](docs/reference/control-plane.md) | Run caller-owned policy bundles that fail closed |
| [reference/registry.md](docs/reference/registry.md) | Publish revocation and refresh PEP caches |
| [reference/otel-evidence.md](docs/reference/otel-evidence.md) | Correlate five spans with receipts and raise `agentid.mismatch` |
| [reference/erasure-executor.md](docs/reference/erasure-executor.md) | Execute and receipt deletion across systems |
| [reference/long-horizon-evidence.md](docs/reference/long-horizon-evidence.md) | Anchor the ledger head with RFC 3161 or customer keys |
| [reference/hardening.md](docs/reference/hardening.md) | Read measured coverage, fuzz results and unresolved gaps |
| [reference/control-plane.md](docs/reference/control-plane.md) | See caller-owned policy bundles, fail-closed caches and pilot surface |

## Evidence, not adjectives

142 Go tests, race-clean parsers, fuzz targets, 23 pinned cross-language vectors and a frozen Python conformance oracle. Delegations and receipts carry ES256 and ML-DSA-65 signatures; the Go verifier checks both. The Python oracle reports `PARTIAL` for PQ signatures by design.

Every claim about a standard is checked against the normative text in [reference/standards-matrix.md](docs/reference/standards-matrix.md), with the audit trail and our own corrections in [reference/verification-log.md](docs/reference/verification-log.md).

## Limits

Not tamper-proof storage: receipts are tamper-evident. Not a certified product. Not a substitute for your own threat model: see [security/threat-model.md](docs/security/threat-model.md). CMS chain verification and second-language PQ verification remain unresolved; see [reference/hardening.md](docs/reference/hardening.md).

## Pilot bar

One live tool path. 50 receipts per week for two weeks. The only success signal is an operator who can wire an existing MCP path and re-derive the decision from the bundle without calling us.

## Contact

- Security issues: super.agent.universe@gmail.com (see [SECURITY.md](SECURITY.md))
- Bugs and feature requests: GitHub issues
- Design critique: open an issue naming the constraint you disagree with

## License

All rights reserved. No copying or commercial use without the owner's prior written permission. See [LICENSE](LICENSE).
