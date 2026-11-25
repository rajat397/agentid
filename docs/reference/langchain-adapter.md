# LangChain/LangGraph adapter — one middleware line

`AgentIDMiddleware` wraps `wrap_tool_call` around every tool call. Tools and
agent construction stay unchanged except for one argument:

```python
from agentid_langchain import AgentIDMiddleware

agent = create_agent(
    model=..., tools=..., middleware=[AgentIDMiddleware("http://127.0.0.1:8092")]
)
```

Start the local decision service with
`agentid hook-serve --config agentid.json --addr 127.0.0.1:8092`.

The Python adapter is intentionally thin: it sends `tool_name` and
`tool_input` to `/v1/pre-tool`, and fails closed on any error, timeout or
unexpected response. The Go service performs validation, mints receipts, and
creates approval requests. Authority fields come from operator config on the
service side, not from the agent.

Both sync and async middleware hooks are provided. Adversarial tests cover
allow, deny without handler execution, unavailable service and malformed
response.
