# Google ADK adapter — one callback on the agent

```python
from agentid_adk import AgentIDBeforeToolCallback

agent = LlmAgent(
    name="agent", model=..., tools=...,
    before_tool_callback=AgentIDBeforeToolCallback("http://127.0.0.1:8092"),
)
```

The callback has the exact ADK signature `(tool, args, tool_context)`. It
returns `None` on allow, so the tool executes normally. A truthy dict on deny
short-circuits execution and carries the receipt id and any approval request
in the result. Any error fails closed.

`AsyncAgentIDBeforeToolCallback` is the async equivalent. The decision is made
by the local Go service at `/v1/pre-tool`; authority fields are resolved from
operator config there, not from agent arguments.

Adversarial tests cover allow, deny short-circuit, unavailable service and
malformed response.
