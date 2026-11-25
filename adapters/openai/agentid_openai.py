"""OpenAI Agents SDK tool-input guardrail backed by agentid.

Attach without editing a tool body:
    purchase.tool_input_guardrails = [agentid_tool_guardrail("http://127.0.0.1:8092")]

RunHooks cannot block; a tool-input guardrail can. Any service or parse error
rejects the content, so the tool does not execute.
"""

import json
from urllib.request import Request, urlopen

try:
    from agents import ToolGuardrailFunctionOutput
except ImportError:
    class ToolGuardrailFunctionOutput:
        def __init__(self, behavior, message=None, output_info=None):
            self.behavior = behavior
            self.message = message
            self.output_info = output_info

        @classmethod
        def allow(cls, output_info=None):
            return cls("allow", output_info=output_info)

        @classmethod
        def reject_content(cls, message, output_info=None):
            return cls("reject_content", message=message, output_info=output_info)


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
    return "; ".join(parts)


def agentid_tool_guardrail(endpoint, timeout=2.0):
    def guardrail(data):
        context = getattr(data, "context", None)
        name = getattr(context, "qualified_tool_name", None) or getattr(context, "tool_name", "")
        raw = getattr(context, "tool_arguments", "{}") or "{}"
        try:
            args = json.loads(raw)
        except (TypeError, ValueError):
            return ToolGuardrailFunctionOutput.reject_content(
                "agentid blocked the tool call: invalid tool arguments"
            )
        decision = decide(endpoint, name, args, timeout)
        if decision["allow"]:
            return ToolGuardrailFunctionOutput.allow()
        return ToolGuardrailFunctionOutput.reject_content(
            "agentid blocked the tool call: " + _message(decision)
        )

    return guardrail


def attach_guardrail(tool, endpoint, timeout=2.0):
    guardrails = list(getattr(tool, "tool_input_guardrails", []) or [])
    guardrails.append(agentid_tool_guardrail(endpoint, timeout))
    tool.tool_input_guardrails = guardrails
    return tool
