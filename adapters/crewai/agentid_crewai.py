"""CrewAI global pre-tool hook backed by agentid.

CrewAI swallows exceptions other than `HookAborted`, so every denial and every
decision-service failure raises `HookAborted` explicitly. An allow returns
None and the tool runs normally.
"""

import json
from urllib.request import Request, urlopen

try:
    from crewai.hooks import HookAborted
except ImportError:
    class HookAborted(Exception):
        def __init__(self, reason="", source=""):
            super().__init__(reason)
            self.reason = reason
            self.source = source


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


def AgentIDPreToolHook(endpoint, timeout=2.0):
    """Return a PRE_TOOL_CALL hook for `@on(InterceptionPoint.PRE_TOOL_CALL)`."""

    def before_hook(ctx):
        decision = decide(endpoint, getattr(ctx, "tool_name", ""),
                          getattr(ctx, "tool_input", {}), timeout)
        if decision["allow"]:
            return None
        parts = [decision.get("reason", "blocked")]
        for key in ("receipt_id", "approval_request_id"):
            if decision.get(key):
                parts.append(f"{key}={decision[key]}")
        raise HookAborted(reason="; ".join(parts), source="agentid")

    return before_hook
