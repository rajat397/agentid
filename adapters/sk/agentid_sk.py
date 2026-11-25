"""Semantic Kernel filter backed by agentid's local decision service.

Register as:
    @kernel.filter(FilterTypes.FUNCTION_INVOCATION)
    async def gate(context, next): ...

`agentid_filter(endpoint)` returns that function. It only calls `next` on
allow, so a denial or any service error blocks execution.
"""

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


def _message(decision):
    parts = [decision.get("reason", "blocked")]
    for key in ("receipt_id", "approval_request_id"):
        if decision.get(key):
            parts.append(f"{key}={decision[key]}")
    return "agentid blocked the function call: " + "; ".join(parts)


def agentid_filter(endpoint, timeout=2.0):
    async def filter_fn(context, next):
        function = getattr(context, "function", None)
        name = getattr(function, "name", "") if function is not None else ""
        arguments = getattr(context, "arguments", {}) or {}
        decision = decide(endpoint, name, arguments, timeout)
        if not decision["allow"]:
            context.result = _message(decision)
            return
        await next(context)

    return filter_fn
