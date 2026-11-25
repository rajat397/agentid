# OpenAI Agents SDK adapter — tool-input guardrail

`RunHooks` are observational and cannot block. The blocking seam is a
`tool_input_guardrail`, attached without changing the tool body:

```python
from agentid_openai import attach_guardrail

attach_guardrail(purchase_tool, "http://127.0.0.1:8092")
```

Or decorate at definition time with
`@tool(tool_input_guardrails=[agentid_tool_guardrail("http://127.0.0.1:8092")])`.
For MCP tools, set the guardrail once at the local MCP server to cover every
tool it exposes.

On allow the guardrail returns `allow()`. On deny, or on any service/parse
error, it returns `reject_content(...)` with the receipt and approval request
ids, so the tool never executes. Authority fields are resolved server-side
from operator config, not from `tool_arguments`.

Adversarial tests cover allow, deny, unavailable service and malformed
response.
