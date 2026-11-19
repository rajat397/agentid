# MCP wrapper — the policy enforcement point that holds credentials

The agent talks JSON-RPC to this wrapper. The wrapper holds the downstream
credential, decides, calls the tool only on allow, and mints a receipt either
way. The agent has no API to obtain the credential.

## Trust boundary

- **Operator config owns authority**: tool → action/system, resource type,
  `stage`, `provenance`, `sensitivity_tier`, `budget_key`, allowed argument names.
- **Agent supplies only allowlisted arguments** (e.g. `amount`, `currency`,
  `account`). Any attempt to pass `stage`, `provenance`, `authority` or other
  authority fields is discarded — the mapping overwrites them.
- Validation uses the signed delegation chain, profile, signer key registry and
  (when present) a status token. A stale or unusable status token prevents
  wrapper startup (fail closed).
- On allow: downstream HTTP call with `Authorization: Bearer <credential>` from
  an environment variable named in config; no credential in config/log/receipt.
- On deny: JSON-RPC `-32000` with `error.data.receipt_id` and no downstream call.
- Every `tools/call` — allowed or denied — produces a receipt in the wrapper's
  ledger. `tools/list` advertises names only.

## Commands

```
agentid mock-ads --credential-env MOCK_ADS_TOKEN --addr 127.0.0.1:8091
agentid mcp-serve --config mcp.json --addr 127.0.0.1:8090
```

Config file fields: `tools[]`, `delegations` (JSONL), `profile` (JSON),
`root_key` (PEM), `signer_key` (PEM), optional `status_token`, `status_keys`,
`approval`, `fleet`. Credentials are referenced by env var name only.

## Falsifier

An unauthorized `tools/call` reaches downstream, a denial has no receipt, an
agent-supplied authority field overrides the mapping, or the credential appears
in a tool result/error/receipt — `mcp_test.go` attacks all four.
