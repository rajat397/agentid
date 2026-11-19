package agentid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// AgentSpanAttributes is the provisional gen_ai.agent.identity.* span schema.
// Status: DEVELOPMENT — nothing here is ratified by OpenTelemetry.
type AgentSpanAttributes struct {
	Operation         string
	AgentID           string
	AgentName         string
	AgentTypeID       string
	AgentInstanceID   string
	AgentIdentityID   string
	AgentIdentityName string
	AgentRole         string
	ParentAgentID     string
	SpawnReason       string
	Model             string
	DelegationID      string
	Decision          string
	Obligations       []string
	Constraints       map[string]any
}

// TypeID is a content hash over an agent's defining inputs.
func TypeID(parts ...string) string {
	for i, part := range parts {
		if part == "" {
			parts[i] = "∅"
		}
	}
	joined := strings.Join(parts, "\x1f")
	sum := sha256.Sum256([]byte(joined))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SpanAttributes projects the agent identity fields into OTel attribute names.
func SpanAttributes(a AgentSpanAttributes) map[string]any {
	attrs := map[string]any{
		"gen_ai.operation.name": a.Operation,
		"gen_ai.agent.id":       a.AgentID,
		"gen_ai.agent.name":     a.AgentName,
	}
	if a.AgentTypeID != "" {
		attrs["gen_ai.agent.type.id"] = a.AgentTypeID
	}
	attrs["gen_ai.agent.instance.id"] = a.AgentInstanceID
	if a.AgentIdentityID != "" {
		attrs["gen_ai.agent.identity.id"] = a.AgentIdentityID
	}
	if a.AgentIdentityName != "" {
		attrs["gen_ai.agent.identity.name"] = a.AgentIdentityName
	}
	if a.AgentRole != "" {
		attrs["gen_ai.agent.role"] = a.AgentRole
	}
	if a.ParentAgentID != "" {
		attrs["gen_ai.agent.parent_id"] = a.ParentAgentID
	}
	if a.SpawnReason != "" {
		attrs["gen_ai.agent.spawn_reason"] = a.SpawnReason
	}
	if a.Model != "" {
		attrs["gen_ai.request.model"] = a.Model
	}
	if a.DelegationID != "" {
		attrs["agent.authority.delegation_id"] = a.DelegationID
	}
	if a.Decision != "" {
		attrs["agent.authority.decision"] = a.Decision
	}
	if len(a.Obligations) > 0 {
		attrs["agent.authority.obligations"] = strings.Join(a.Obligations, ",")
	}
	if len(a.Constraints) > 0 {
		keys := make([]string, 0, len(a.Constraints))
		for key := range a.Constraints {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, fmt.Sprintf("%s:%v", key, a.Constraints[key]))
		}
		attrs["agent.authority.constraints"] = strings.Join(parts, " ")
	}
	return attrs
}

// EmitAgentSpan writes one span as a JSON line. No external SDK required:
// the schema is the point, not a particular exporter.
func EmitAgentSpan(a AgentSpanAttributes, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	span := map[string]any{
		"name":       a.Operation + " " + a.AgentName,
		"attributes": SpanAttributes(a),
		"status":     "DEVELOPMENT",
	}
	encoder := json.NewEncoder(out)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(span)
}
