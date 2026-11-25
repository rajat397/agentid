package agentid

import (
	"context"
	"fmt"
	"strings"
)

// ClaudeHookAdapter maps Claude Code PreToolUse events into the same PEP used
// by MCP. An allowed call produces no JSON decision, so normal permission flow
// continues. A blocked call returns a deny decision with receipt evidence.
type ClaudeHookAdapter struct {
	wrapper *MCPWrapper
}

func NewClaudeHookAdapter(wrapper *MCPWrapper) *ClaudeHookAdapter {
	return &ClaudeHookAdapter{wrapper: wrapper}
}

func (a *ClaudeHookAdapter) ProcessHook(ctx context.Context, input []byte) ([]byte, error) {
	value, err := DecodeJSON(input)
	if err != nil {
		return claudeDeny("malformed hook input"), nil
	}
	event := AsMap(value)
	toolName := stringField(event, "tool_name")
	if toolName == "" || !a.wrapper.HasTool(toolName) {
		return nil, nil
	}
	request := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": toolName, "arguments": AsMap(event["tool_input"]),
		},
	}
	response := a.wrapper.HandleRPC(ctx, request)
	if AsMap(response["error"]) == nil {
		return nil, nil
	}
	errorObject := AsMap(response["error"])
	data := AsMap(errorObject["data"])
	reason := stringField(errorObject, "message")
	details := []string{reason}
	if id := stringField(data, "receipt_id"); id != "" {
		details = append(details, "receipt "+id)
	}
	if id := stringField(data, "approval_request_id"); id != "" {
		details = append(details, "approval request "+id)
	}
	return claudeDeny(strings.Join(details, "; ")), nil
}

func claudeDeny(reason string) []byte {
	value := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": fmt.Sprintf("agentid blocked the call: %s", reason),
		},
	}
	data, _ := CanonicalJSON(value)
	return data
}
