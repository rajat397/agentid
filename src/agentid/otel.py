"""OTel-native emission — a minimal agent-identity span schema.

Status: DEVELOPMENT / provisional. The attribute names below follow the
proposed ``gen_ai.agent.identity.*`` semantic conventions (OpenTelemetry
GenAI semantic conventions, currently at Development status). Nothing in
this module is ratified. Treat it as a reference for what an SDK would emit,
not as a settled standard.

Design:
  * ``agent.type.id``   — content hash over the agent's defining inputs
  * ``agent.instance.id`` — unique per invocation
  * ``agent.identity.id`` / ``agent.identity.name`` — the authenticating identity
    (MAY be a SPIFFE ID), distinct from the deployed resource (``agent.id``)
  * ``agent.authority.*`` — the delegation, constraints and approval that
    conventional OTel does not express. This is the project's reason to exist.

Spans are exported via the OTel SDK if ``opentelemetry-sdk`` is installed.
If it is not, emission fails loudly and specifically — never silently.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class AgentSpanAttributes:
    """The attributes an agent execution should carry. Nothing here is secret."""

    operation: str                 # create_agent / invoke_agent / invoke_workflow
    agent_id: str                  # gen_ai.agent.id — deployed resource
    agent_name: str                # gen_ai.agent.name
    agent_type_id: str | None      # content hash of defining inputs
    agent_instance_id: str         # unique per invocation
    agent_identity_id: str | None  # the authenticating identity (MAY be SPIFFE)
    agent_identity_name: str | None
    agent_role: str | None         # planner / worker / critic ...
    parent_agent_id: str | None
    spawn_reason: str | None
    model: str | None
    delegation_id: str | None      # agent.authority.delegation_id
    decision: str | None           # agent.authority.decision
    obligations: tuple[str, ...]   # agent.authority.obligations (e.g. cosign_above)
    constraints: dict[str, Any]    # agent.authority.constraints (permissions, caps)


def type_id(*parts: str) -> str:
    """Content hash over an agent's defining inputs."""
    joined = "\x1f".join(p if p else "∅" for p in parts)
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _import_sdk():
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor, ConsoleSpanExporter
        return trace, TracerProvider, SimpleSpanProcessor, ConsoleSpanExporter
    except Exception as e:  # pragma: no cover - import guard
        raise RuntimeError(
            "opentelemetry-sdk is required for agentid.otel. "
            "Install with: pip install 'agentid[otel]'"
        ) from e


def emit_agent_span(a: AgentSpanAttributes, tracer_provider=None) -> None:
    """Emit one agent-execution span. Requires opentelemetry-sdk."""
    trace, TracerProvider, SimpleSpanProcessor, ConsoleSpanExporter = _import_sdk()

    provider = tracer_provider or _default_provider(trace, TracerProvider, SimpleSpanProcessor, ConsoleSpanExporter)
    tracer = trace.get_tracer("agentid", "0.1.0", tracer_provider=provider)

    attrs: dict[str, Any] = {
        "gen_ai.operation.name": a.operation,
        "gen_ai.agent.id": a.agent_id,
        "gen_ai.agent.name": a.agent_name,
    }
    if a.agent_type_id:
        attrs["gen_ai.agent.type.id"] = a.agent_type_id
    attrs["gen_ai.agent.instance.id"] = a.agent_instance_id
    if a.agent_identity_id:
        attrs["gen_ai.agent.identity.id"] = a.agent_identity_id
    if a.agent_identity_name:
        attrs["gen_ai.agent.identity.name"] = a.agent_identity_name
    if a.agent_role:
        attrs["gen_ai.agent.role"] = a.agent_role
    if a.parent_agent_id:
        attrs["gen_ai.agent.parent_id"] = a.parent_agent_id
    if a.spawn_reason:
        attrs["gen_ai.agent.spawn_reason"] = a.spawn_reason
    if a.model:
        attrs["gen_ai.request.model"] = a.model
    # Authority — the dimension no OTel convention expresses today
    if a.delegation_id:
        attrs["agent.authority.delegation_id"] = a.delegation_id
    if a.decision:
        attrs["agent.authority.decision"] = a.decision
    if a.obligations:
        attrs["agent.authority.obligations"] = ",".join(a.obligations)
    if a.constraints:
        attrs["agent.authority.constraints"] = str(sorted(a.constraints.items()))

    with tracer.start_as_current_span(f"{a.operation} {a.agent_name}", attributes=attrs):
        pass


_provider_singleton = None

def _default_provider(trace, TracerProvider, SimpleSpanProcessor, ConsoleSpanExporter):
    global _provider_singleton
    if _provider_singleton is None:
        provider = TracerProvider()
        processor = SimpleSpanProcessor(ConsoleSpanExporter())
        provider.add_span_processor(processor)
        _provider_singleton = provider
    return _provider_singleton


def demo_span_attributes() -> AgentSpanAttributes:
    """A concrete, realistic instance — used by tests and by the docs."""
    return AgentSpanAttributes(
        operation="invoke_agent",
        agent_id="arn:agent:acme-retail:marketing-agent/prod",
        agent_name="marketing-agent",
        agent_type_id=type_id("sha256:3f9a…c1", "agentid/1", "claude-opus-5", "v2.4.1"),
        agent_instance_id="01HXYZ…K7",
        agent_identity_id="spiffe://example.trust/agent/marketing-agent",
        agent_identity_name="marketing-agent",
        agent_role="worker",
        parent_agent_id="orchestrator-01",
        spawn_reason="initial_decomposition",
        model="claude-opus-5",
        delegation_id="dlg_01J8X2K9Q4T7W",
        decision="allowed",
        obligations=("cosign_above",),
        constraints={"permissions": "ad.credit.purchase@meta-ads", "max_amount": "2000.00"},
    )
