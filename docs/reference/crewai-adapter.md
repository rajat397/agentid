# CrewAI adapter — global pre-tool hook

```python
from crewai.hooks import on, InterceptionPoint
from agentid_crewai import AgentIDPreToolHook

@on(InterceptionPoint.PRE_TOOL_CALL)
def agentid_gate(ctx):
    return AgentIDPreToolHook("http://127.0.0.1:8092")(ctx)
```

Or register once with a `tools=[...]` filter to scope it to consequential
tools. An allow returns `None`; a deny raises `HookAborted` with the receipt id
and any approval request id in its reason. CrewAI swallows other exceptions,
so the adapter deliberately raises only `HookAborted` on every failure path,
including an unavailable decision service or a malformed response.

The decision is made by the local Go service; authority fields are resolved
from operator config there, not from `ctx.tool_input`.

Adversarial tests cover allow, deny, unavailable service and malformed
response.
