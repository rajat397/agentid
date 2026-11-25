package agentid

import (
	"context"
	"strings"
	"testing"
)

func hookTestWrapper(t *testing.T, withWorkflow bool) *MCPWrapper {
	t.Helper()
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "hook_key")
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", map[string]any{
			"permissions": []any{map[string]any{
				"action": "ad.credit.purchase", "system": "meta-ads"}},
			"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
			"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
		}, "2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	config := MCPWrapperConfig{
		Tools: []ToolMapping{{
			Name: "purchase", Action: "ad.credit.purchase", System: "meta-ads",
			ResourceType: "ad_credit_account",
			AllowedArgs:  []string{"amount", "currency", "stage", "system", "provenance"},
			Stage:        StageSideEffect, Provenance: ProvenanceTrusted,
		}},
		Chain: []Delegation{delegation}, Profile: ExampleProfile(),
		RootKeyPEM: publicPEM, Signer: signer,
	}
	if withWorkflow {
		config.ApprovalWorkflow = NewApprovalWorkflow()
	}
	wrapper, err := NewMCPWrapper(config)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper
}

func hookInput(t *testing.T, tool string, amount string) []byte {
	t.Helper()
	value := map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "s1",
		"tool_name":       tool,
		"tool_input": map[string]any{
			"amount": amount, "currency": "USD",
			"stage": StagePlan, "system": "evil-system",
		},
	}
	data, err := CanonicalJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestClaudeHookAllowsWithoutDecision(t *testing.T) {
	wrapper := hookTestWrapper(t, false)
	adapter := NewClaudeHookAdapter(wrapper)
	out, err := adapter.ProcessHook(context.Background(), hookInput(t, "purchase", "100.00"))
	if err != nil || len(out) != 0 {
		t.Fatalf("allowed hook returned a decision: %s %v", out, err)
	}
	if len(wrapper.Ledger().Receipts) != 1 {
		t.Fatalf("allowed hook minted no receipt: %d", len(wrapper.Ledger().Receipts))
	}
}

func TestClaudeHookDeniesOverCap(t *testing.T) {
	adapter := NewClaudeHookAdapter(hookTestWrapper(t, false))
	out, err := adapter.ProcessHook(context.Background(), hookInput(t, "purchase", "5000.00"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "permissionDecision") ||
		!strings.Contains(string(out), "deny") ||
		!strings.Contains(string(out), "receipt ") {
		t.Fatalf("invalid denial output: %s", out)
	}
}

func TestClaudeHookAuthorityFieldsCannotBeOverridden(t *testing.T) {
	wrapper := hookTestWrapper(t, false)
	adapter := NewClaudeHookAdapter(wrapper)
	_, err := adapter.ProcessHook(context.Background(), hookInput(t, "purchase", "100.00"))
	if err != nil {
		t.Fatal(err)
	}
	receipt := wrapper.Ledger().Receipts[0]
	if stringField(receipt.Resource, "stage") != StageSideEffect {
		t.Fatalf("stage override accepted: %+v", receipt.Resource)
	}
	if !strings.Contains(stringValue(receipt.Decision["constraints_evaluated"]), "meta-ads") {
		t.Fatal("system override accepted")
	}
}

func TestClaudeHookUnmappedToolAndMalformedInput(t *testing.T) {
	adapter := NewClaudeHookAdapter(hookTestWrapper(t, false))
	out, _ := adapter.ProcessHook(context.Background(), hookInput(t, "Read", "10.00"))
	if len(out) != 0 {
		t.Fatalf("unmapped tool produced a decision: %s", out)
	}
	out, err := adapter.ProcessHook(context.Background(), []byte("{broken"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "deny") {
		t.Fatalf("malformed input did not fail closed: %s", out)
	}
}

func TestClaudeHookApprovalRequest(t *testing.T) {
	adapter := NewClaudeHookAdapter(hookTestWrapper(t, true))
	out, err := adapter.ProcessHook(context.Background(), hookInput(t, "purchase", "1500.00"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "approval request ") {
		t.Fatalf("approval request missing: %s", out)
	}
}
