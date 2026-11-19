package agentid

import (
	"bytes"
	"strings"
	"testing"
)

func TestSpanAttributesCarryAuthority(t *testing.T) {
	attributes := SpanAttributes(AgentSpanAttributes{
		Operation: "invoke_agent", AgentID: "marketing-agent", AgentName: "marketing",
		AgentTypeID: TypeID("v1", "prompt"), AgentInstanceID: "inst_1",
		AgentIdentityID: "spiffe://example.trust/agent/marketing-agent",
		DelegationID:    "dlg_1", Decision: "valid",
		Obligations: []string{"cosign_above"},
		Constraints: map[string]any{"permissions": "ad.credit.purchase@meta-ads"},
	})
	for _, key := range []string{
		"gen_ai.operation.name", "gen_ai.agent.id", "gen_ai.agent.type.id",
		"gen_ai.agent.instance.id", "gen_ai.agent.identity.id",
		"agent.authority.delegation_id", "agent.authority.decision",
		"agent.authority.obligations", "agent.authority.constraints",
	} {
		if _, ok := attributes[key]; !ok {
			t.Errorf("missing span attribute %s", key)
		}
	}
}

func TestTypeIDIsDeterministic(t *testing.T) {
	first := TypeID("prompt-v1", "model-x")
	if first != TypeID("prompt-v1", "model-x") || first == TypeID("prompt-v1", "model-y") {
		t.Fatal("TypeID is not a stable content hash")
	}
}

func TestEmitAgentSpanWritesDevelopmentSpan(t *testing.T) {
	var out bytes.Buffer
	err := EmitAgentSpan(AgentSpanAttributes{
		Operation: "invoke_agent", AgentID: "a", AgentName: "agent",
		DelegationID: "dlg_1", Decision: "valid",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "DEVELOPMENT") ||
		!strings.Contains(out.String(), "agent.authority.delegation_id") {
		t.Fatalf("span missing authority or maturity: %s", out.String())
	}
}
