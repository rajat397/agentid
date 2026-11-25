"""LangChain/LangGraph middleware for agentid pre-tool decisions.

Usage:
    agent = create_agent(model=..., tools=..., middleware=[
        AgentIDMiddleware("http://127.0.0.1:8092")
    ])

The middleware adds one construction line; tools and agent code stay unchanged.
Every error fails closed: no decision means no tool call.
"""

import asyncio
import inspect
import json
from urllib.request import Request, urlopen


class AgentIDDenied(Exception):
    """Raised when the PEP denies a tool call."""


def decide(endpoint, tool_name, tool_input, timeout=2.0):
    url = endpoint.rstrip("/") + "/v1/pre-tool"
    payload = json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input}
    ).encode("utf-8")
    try:
        request = Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            body = json.load(response)
        if not isinstance(body, dict) or body.get("allow") is not True:
            reason = body.get("reason", "invalid decision") if isinstance(body, dict) else "invalid decision"
            return {
                "allow": False, "reason": reason,
                "receipt_id": body.get("receipt_id"),
                "approval_request_id": body.get("approval_request_id"),
            }
        return body
    except Exception as exc:
        return {"allow": False, "reason": f"decision service unavailable: {exc}"}


class AgentIDMiddleware:
    def __init__(self, endpoint, timeout=2.0):
        self.endpoint = endpoint
        self.timeout = timeout

    def _decide(self, request):
        call = getattr(request, "tool_call", {}) or {}
        return decide(
            self.endpoint,
            call.get("name", ""),
            call.get("args", {}),
            self.timeout,
        )

    def wrap_tool_call(self, request, handler):
        decision = self._decide(request)
        if not decision["allow"]:
            raise AgentIDDenied(_message(decision))
        return handler(request)

    async def awrap_tool_call(self, request, handler):
        decision = await asyncio.to_thread(self._decide, request)
        if not decision["allow"]:
            raise AgentIDDenied(_message(decision))
        result = handler(request)
        if inspect.isawaitable(result):
            result = await result
        return result


def _message(decision):
    parts = [decision.get("reason", "blocked")]
    for key in ("receipt_id", "approval_request_id"):
        if decision.get(key):
            parts.append(f"{key}={decision[key]}")
    return "; ".join(parts)
