package agentid

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type HookDecision struct {
	Allow             bool   `json:"allow"`
	ReceiptID         string `json:"receipt_id,omitempty"`
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	Reason            string `json:"reason,omitempty"`
}

// ClaudeHookAdapter maps tool events into the same PEP used by MCP.
type ClaudeHookAdapter struct {
	wrapper *MCPWrapper
}

func NewClaudeHookAdapter(wrapper *MCPWrapper) *ClaudeHookAdapter {
	return &ClaudeHookAdapter{wrapper: wrapper}
}

// Decide is the framework-neutral pre-tool decision. Denial fails closed.
func (a *ClaudeHookAdapter) Decide(ctx context.Context, input []byte) HookDecision {
	value, err := DecodeJSON(input)
	if err != nil {
		return HookDecision{Reason: "malformed hook input"}
	}
	event := AsMap(value)
	toolName := stringField(event, "tool_name")
	if toolName == "" || !a.wrapper.HasTool(toolName) {
		return HookDecision{Allow: true}
	}
	request := map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name": toolName, "arguments": AsMap(event["tool_input"]),
		},
	}
	response := a.wrapper.HandleRPC(ctx, request)
	if AsMap(response["error"]) == nil {
		meta := AsMap(AsMap(response["result"])["_meta"])
		return HookDecision{Allow: true, ReceiptID: stringField(meta, "receipt_id")}
	}
	errorObject := AsMap(response["error"])
	data := AsMap(errorObject["data"])
	return HookDecision{
		ReceiptID:         stringField(data, "receipt_id"),
		ApprovalRequestID: stringField(data, "approval_request_id"),
		Reason:            stringField(errorObject, "message"),
	}
}

func (a *ClaudeHookAdapter) ProcessHook(ctx context.Context, input []byte) ([]byte, error) {
	decision := a.Decide(ctx, input)
	if decision.Allow {
		return nil, nil
	}
	details := []string{decision.Reason}
	if decision.ReceiptID != "" {
		details = append(details, "receipt "+decision.ReceiptID)
	}
	if decision.ApprovalRequestID != "" {
		details = append(details, "approval request "+decision.ApprovalRequestID)
	}
	value := map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": fmt.Sprintf("agentid blocked the call: %s", strings.Join(details, "; ")),
		},
	}
	data, _ := CanonicalJSON(value)
	return data, nil
}

// HTTPHookHandler exposes the framework-neutral decision over localhost.
func HTTPHookHandler(adapter *ClaudeHookAdapter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pre-tool", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, adapter.Decide(r.Context(), body))
	})
	return mux
}
