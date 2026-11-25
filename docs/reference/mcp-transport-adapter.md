# MCP transport adapter — one command, no agent-code change

`agentid wrap --config agentid.json -- <mcp-server-command>` starts the MCP
server as a child process and sits between it and the client. MCP stdio is
newline-delimited JSON-RPC (spec 2026-07-28), so the proxy can be transport-exact:

- `initialize`, notifications and ordinary messages pass through unchanged.
- `tools/call` is intercepted. Authority fields (`action`, `system`,
  `resource_type`, `stage`, `provenance`, `sensitivity_tier`, `aud`) are taken
  from operator config, never from tool arguments.
- The PEP validates, mints a receipt, and either forwards the original request
  or returns JSON-RPC `-32000` with the receipt id and, where relevant, an
  approval request id. Denied calls never reach the server.
- Allowed replies are annotated with `_meta.receipt_id` so client and server
  traces join to the same evidence artifact.

Adversarial tests cover over-cap denial, approval escalation, agent-supplied
authority fields, malformed JSON, cancellation pass-through, and server
response annotation.

## Status and limits

Stdio is the first shipped seam. Streamable HTTP uses the same `MCPProxy`
core but needs an HTTP reverse-proxy front end; that is the next step in this
adapter. The config file is the current contract; `agentid init` will generate
it in a later step. No vendor-specific MCP server changes are required.
