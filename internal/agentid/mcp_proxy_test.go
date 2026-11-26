package agentid

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func proxyTestWrapper(t *testing.T, withWorkflow bool) *MCPWrapper {
	t.Helper()
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "proxy_key")
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

func proxyCall(t *testing.T, amount string) []byte {
	t.Helper()
	return MCPRequestJSON(7, "purchase", map[string]any{
		"amount": amount, "currency": "USD",
		"stage":  StagePlan,
		"system": "evil-system",
	})
}

func TestMCPProxyForwardsAllowedAndAnnotatesResponse(t *testing.T) {
	wrapper := proxyTestWrapper(t, false)
	proxy := NewMCPProxy(wrapper)
	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "100.00"))
	if !forward || response != nil {
		t.Fatalf("allowed call was not forwarded: forward=%v response=%s", forward, response)
	}
	serverResponse := []byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	out, err := proxy.ProcessServerResponse(serverResponse)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	meta := AsMap(AsMap(decoded["result"])["_meta"])
	if stringField(meta, "receipt_id") == "" {
		t.Fatalf("server response lacks receipt binding: %s", out)
	}
}

func TestMCPProxyDeniesOverCapWithoutForward(t *testing.T) {
	proxy := NewMCPProxy(proxyTestWrapper(t, false))
	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "5000.00"))
	if forward {
		t.Fatal("over-cap call was forwarded to the server")
	}
	if !strings.Contains(string(response), "-32000") || !strings.Contains(string(response), "receipt_id") {
		t.Fatalf("denial lacks error code and receipt: %s", response)
	}
}

func TestMCPProxyAuthorityFieldsCannotBeOverridden(t *testing.T) {
	wrapper := proxyTestWrapper(t, false)
	proxy := NewMCPProxy(wrapper)
	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "100.00"))
	if !forward || response != nil {
		t.Fatalf("call was not forwarded: %s", response)
	}
	receipt := wrapper.Ledger().Receipts[0]
	if stringField(receipt.Resource, "stage") != StageSideEffect {
		t.Fatalf("agent-supplied stage overrode mapping: %+v", receipt.Resource)
	}
	if !strings.Contains(stringValue(receipt.Decision["constraints_evaluated"]), "meta-ads") {
		t.Fatal("system mapping was not applied")
	}
}

func TestMCPProxyPassesThroughNonToolAndMalformed(t *testing.T) {
	proxy := NewMCPProxy(proxyTestWrapper(t, false))
	initLine := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	forward, response := proxy.ProcessClient(context.Background(), initLine)
	if !forward || response != nil {
		t.Fatal("initialize was not passed through")
	}
	forward, response = proxy.ProcessClient(context.Background(), []byte("{broken"))
	if forward || !strings.Contains(string(response), "-32700") {
		t.Fatalf("malformed JSON was forwarded or not rejected: %s", response)
	}
	cancel := []byte(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	forward, _ = proxy.ProcessClient(context.Background(), cancel)
	if !forward {
		t.Fatal("cancellation notification was not passed through")
	}
}

func TestMCPProxyShadowForwardsDeniedCallAndAnnotatesVerdict(t *testing.T) {
	wrapper := proxyTestWrapper(t, false)
	wrapper.config.Mode = OperatorModeShadow
	proxy := NewMCPProxy(wrapper)
	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "5000.00"))
	if !forward || response != nil {
		t.Fatalf("shadow call was not forwarded: forward=%v response=%s", forward, response)
	}
	serverResponse := []byte(`{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"ok"}]}}`)
	out, err := proxy.ProcessServerResponse(serverResponse)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	meta := AsMap(AsMap(decoded["result"])["_meta"])
	shadow := AsMap(meta["agentid_shadow"])
	if stringField(shadow, "verdict") != "deny" || stringField(shadow, "receipt_id") == "" {
		t.Fatalf("shadow verdict not annotated: %s", out)
	}
}

func TestMCPProxyRaisesApprovalRequest(t *testing.T) {
	proxy := NewMCPProxy(proxyTestWrapper(t, true))
	forward, response := proxy.ProcessClient(context.Background(), proxyCall(t, "1500.00"))
	if forward {
		t.Fatal("call awaiting approval was forwarded")
	}
	if !strings.Contains(string(response), "approval_request_id") {
		t.Fatalf("indeterminate call lacks approval request: %s", response)
	}
}
