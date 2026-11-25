"""AutoGen Core intervention handler backed by agentid's decision service.

Register once on the runtime:
    runtime = SingleThreadedAgentRuntime(
        intervention_handlers=[AgentIDInterventionHandler("http://127.0.0.1:8092")]
    )
"""

import json
from urllib.request import Request, urlopen

try:
    from autogen_core import DefaultInterventionHandler
except ImportError:
    class DefaultInterventionHandler:
        pass

try:
    from autogen_core.tools import ToolException
except ImportError:
    class ToolException(Exception):
        def __init__(self, content="", call_id=None, name=None):
            super().__init__(content)
            self.content = content
            self.call_id = call_id
            self.name = name


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


class AgentIDInterventionHandler(DefaultInterventionHandler):
    def __init__(self, endpoint, timeout=2.0):
        self.endpoint = endpoint
        self.timeout = timeout

    async def on_send(self, message, *, message_context, recipient):
        name = getattr(message, "name", "")
        if not name:
            return message
        decision = decide(self.endpoint, name,
                          getattr(message, "arguments", {}) or {}, self.timeout)
        if not decision["allow"]:
            raise ToolException(
                content=_message(decision),
                call_id=getattr(message, "id", None), name=name,
            )
        return message
