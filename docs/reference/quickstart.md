# Quickstart: first receipt on a real tool path

The fastest path to a verifiable agent action is one command.

```bash
go run ./cmd/agentid quickstart --out ./quickstart
```

Expected output:

```text
first receipt: rcp_...
blocked calls: 1
downstream executed: 1 call(s)
bundle: ./quickstart/quickstart-bundle.json
verify: offline VERIFIED
elapsed: ...
```

## What happened

`quickstart` runs a real enforcement path in-process:

1. generates a local development signer and a narrow delegation;
2. signs a human approval for a $2,000 ad-credit purchase;
3. starts a local downstream tool that accepts only a bearer credential held by the PEP;
4. mounts the MCP HTTP handler with a real auth token;
5. sends one over-cap `$4,500` call and confirms the downstream receives zero calls;
6. sends one approved `$2,000` call and confirms the downstream receives one call;
7. exports a portable evidence bundle with both receipts, the delegation, profile and signer keys;
8. verifies every receipt offline.

This is not an animated demo. The deny/allow outcomes and downstream call counts come from real HTTP handlers. The signer is still a development signer, so use `ExternalSigner` with KMS/HSM for production.

## Verify the bundle yourself

```bash
go run ./cmd/agentid evidence verify --file ./quickstart/quickstart-bundle.json
go run ./cmd/agentid verify-signed --artifact ./quickstart/quickstart-bundle.json
```

## Next

Wrap one real MCP tool path with `agentid wrap --config <profile> -- <mcp-server>`, then move to shadow mode before enforcement. See [operator-config.md](operator-config.md) and [mcp-transport-adapter.md](mcp-transport-adapter.md).
