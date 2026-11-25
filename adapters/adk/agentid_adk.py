"""Google ADK adapter: one `before_tool_callback` on the agent.

A truthy dict returned from the callback short-circuits the tool call, so a
denial never reaches the downstream tool. Any error fails closed.
"""

import asyncio
import json
from urllib.request import Request, urlopen


def decide(endpoint, tool_name, args, timeout=2.0):
    url = endpoint.rstrip("/") + "/v1/pre-tool"
    payload = json.dumps({"tool_name": tool_name, "tool_input": args}).encode("utf-8")
    try:
        with urlopen(Request(url, data=payload,
                             headers={"Content-Type": "application/json"}),
                     timeout=timeout) as response:
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


def AgentIDBeforeToolCallback(endpoint, timeout=2.0):
    """Return a callback with the exact ADK signature (tool, args, tool_context)."""

    def before_tool_callback(tool, args, tool_context):
        name = getattr(tool, "name", "")
        decision = decide(endpoint, name, args, timeout)
        if decision["allow"]:
            return None
        parts = [decision.get("reason", "blocked")]
        for key in ("receipt_id", "approval_request_id"):
            if decision.get(key):
                parts.append(f"{key}={decision[key]}")
        return {"result": "agentid blocked the tool call: " + "; ".join(parts)}

    return before_tool_callback


def AsyncAgentIDBeforeToolCallback(endpoint, timeout=2.0):
    callback = AgentIDBeforeToolCallback(endpoint, timeout)

    async def before_tool_callback(tool, args, tool_context):
        return await asyncio.to_thread(callback, tool, args, tool_context)

    return before_tool_callback
