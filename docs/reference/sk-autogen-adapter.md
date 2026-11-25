# Semantic Kernel and AutoGen Core adapters

Both adapters call the local Go service at `/v1/pre-tool` and fail closed.

## Semantic Kernel

```python
from semantic_kernel.filters import FilterTypes
from agentid_sk import agentid_filter

@kernel.filter(FilterTypes.FUNCTION_INVOCATION)
async def agentid_gate(context, next):
    await agentid_filter("http://127.0.0.1:8092")(context, next)
```

The filter calls `next(context)` only on allow. On deny it sets
`context.result` to a reason carrying the receipt and approval request ids
and does not call `next`, so the function never executes.

## AutoGen Core

```python
from autogen_core import SingleThreadedAgentRuntime
from agentid_autogen import AgentIDInterventionHandler

runtime = SingleThreadedAgentRuntime(
    intervention_handlers=[AgentIDInterventionHandler("http://127.0.0.1:8092")]
)
```

The handler's `on_send` raises `ToolException` on denial and returns the
message unchanged on allow. It is a Core-level seam; the docs do not show an
AgentChat equivalent.

Adversarial tests for both cover allow, deny, unavailable service and
malformed response. Authority fields are resolved server-side from operator
config, not from agent arguments.
