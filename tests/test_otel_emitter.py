"""OTel emitter — attributes are emitted under the proposed names.

Status: DEVELOPMENT. These names follow the OTel GenAI spec's proposed
`gen_ai.agent.identity.*` attribute set; nothing is ratified.
"""

import io
import sys

import pytest

pytest.importorskip("opentelemetry.sdk", reason="opentelemetry-sdk not installed")

from agentid import otel  # noqa: E402


def test_type_id_is_content_addressed_and_stable():
    a = otel.type_id("x", "y")
    b = otel.type_id("x", "y")
    c = otel.type_id("x", "z")
    assert a == b
    assert a != c
    assert a.startswith("sha256:")


def test_demo_attributes_carry_required_identity_fields():
    attrs = otel.demo_span_attributes()
    assert attrs.operation == "invoke_agent"
    assert attrs.agent_type_id.startswith("sha256:")
    assert attrs.agent_identity_id.startswith("spiffe://")
    assert attrs.parent_agent_id == "orchestrator-01"
    assert attrs.delegation_id == "dlg_01J8X2K9Q4T7W"


def test_span_emission_contains_agent_identity_names():
    exporter = _RecordingExporter()
    provider = _make_provider(exporter)
    a = otel.demo_span_attributes()
    otel.emit_agent_span(a, tracer_provider=provider)
    spans = exporter.collected
    attrs = {}
    for span in spans:
        attrs.update(span.attributes or {})
    for name in (
        "gen_ai.operation.name",
        "gen_ai.agent.id",
        "gen_ai.agent.type.id",
        "gen_ai.agent.instance.id",
        "gen_ai.agent.identity.id",
        "gen_ai.agent.identity.name",
        "gen_ai.agent.role",
        "gen_ai.agent.spawn_reason",
        "agent.authority.delegation_id",
        "agent.authority.decision",
        "agent.authority.obligations",
    ):
        assert name in attrs, f"missing attribute: {name}"


class _RecordingExporter:
    def __init__(self):
        self.collected = []

    def export(self, spans):
        self.collected.extend(spans)
        return True

    def shutdown(self):
        pass


def _make_provider(exporter):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider
