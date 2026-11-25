# Claude Code hook adapter — declarative, no agent-code change

`agentid claude-hook --config agentid.json` is a Claude Code `PreToolUse`
command hook. It reads the event JSON on stdin and returns a deny decision
only when the PEP blocks the call. Allowed calls return no decision, so normal
permissions continue.

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__ads__purchase_ad_credit",
        "hooks": [
          { "type": "command", "command": "agentid",
            "args": ["claude-hook", "--config", "/absolute/path/agentid.json"] }
        ]
      }
    ]
  }
}
```

`matcher` must be the real tool name Claude Code uses. For MCP tools that is
`mcp__<server>__<tool>`. The config's tool entries must use the same names;
authority fields come from config, never from `tool_input`.

Adversarial tests cover over-cap denial, authority-field override attempts,
malformed input, unmapped tools, and approval-request creation.

## Status and limits

This is the declarative one-step surface for Claude Code terminal, IDE,
Desktop and cloud sessions, because hooks fire in all of them. It cannot see
model-level intent before a tool call, and a non-blocking hook is not a security
boundary; use deny decisions and normal Claude permissions together.
