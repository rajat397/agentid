package agentid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func mcpTestWrapper(t *testing.T, statusToken string, statusKeys map[string]string,
	statusIdx *int) (*MCPWrapper, *int64, []byte) {
	t.Helper()
	credential := "secret-mock-token"
	t.Setenv("MOCK_ADS_CREDENTIAL", credential)
	var calls int64
	ads := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Errorf("downstream did not receive the wrapper-held credential")
		}
		json.NewEncoder(w).Encode(map[string]any{"order_id": "mock_order_1"})
	}))
	t.Cleanup(ads.Close)

	signer, pub := newSigner(t, "mcp_signer")
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
		"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "marketing-agent",
		constraints, "2030-01-01T00:00:00Z", DelegationOptions{
			Signer: signer, StatusIdx: statusIdx,
		})
	if err != nil {
		t.Fatal(err)
	}
	mapping := ToolMapping{
		Name: "purchase_ad_credit", Action: "ad.credit.purchase", System: "meta-ads",
		ResourceType: "ad_credit_account", ResourceIDField: "account",
		AllowedArgs: []string{"amount", "currency"},
		Stage:       StageSideEffect, Provenance: ProvenanceTrusted,
		DownstreamURL: ads.URL, CredentialEnv: "MOCK_ADS_CREDENTIAL",
	}
	config := MCPWrapperConfig{
		Tools: []ToolMapping{mapping}, Chain: []Delegation{delegation},
		Profile: ExampleProfile(), RootKeyPEM: pub, Signer: signer,
		Fleet: "marketing", StatusToken: statusToken, StatusKeys: statusKeys,
	}
	wrapper, err := NewMCPWrapper(config)
	if err != nil {
		t.Fatal(err)
	}
	return wrapper, &calls, pub
}

func callRPC(wrapper *MCPWrapper, id int, args map[string]any) map[string]any {
	request, _ := DecodeJSON(MCPRequestJSON(id, "purchase_ad_credit", args))
	return wrapper.HandleRPC(context.Background(), AsMap(request))
}

func TestMCPWrapperAllowsAndNeverLeaksCredential(t *testing.T) {
	wrapper, calls, _ := mcpTestWrapper(t, "", nil, nil)
	response := callRPC(wrapper, 1, map[string]any{
		"amount": "100.00", "currency": "USD", "account": "acct_1",
		"stage": "plan", "provenance": "untrusted", "authority": "forged",
	})
	result := AsMap(response["result"])
	if result == nil {
		t.Fatalf("allowed call returned error: %+v", response)
	}
	if atomic.LoadInt64(calls) != 1 {
		t.Fatal("downstream was not called")
	}
	if stringField(AsMap(result["_meta"]), "receipt_id") == "" {
		t.Fatal("result does not carry a receipt id")
	}
	serialized, _ := json.Marshal(response)
	if strings.Contains(string(serialized), "secret-mock-token") {
		t.Fatal("credential leaked into tool result")
	}
	receipt := wrapper.ledger.Receipts[0]
	attributes := AsMap(receipt.Resource["attributes"])
	if stringField(attributes, "stage") != "" || stringField(receipt.Resource, "stage") != StageSideEffect {
		t.Fatalf("agent-supplied stage was not overridden: %+v", receipt.Resource)
	}
	if stringField(receipt.Resource, "stage") != StageSideEffect {
		t.Fatal("mapping stage not recorded")
	}
	receiptJSON, _ := json.Marshal(receipt.ToMap())
	if strings.Contains(string(receiptJSON), "secret-mock-token") ||
		strings.Contains(string(receiptJSON), "forged") {
		t.Fatal("credential or forged authority leaked into receipt")
	}
}

func TestMCPWrapperDeniesWithReceiptAndNoDownstreamCall(t *testing.T) {
	wrapper, calls, _ := mcpTestWrapper(t, "", nil, nil)
	response := callRPC(wrapper, 2, map[string]any{
		"amount": "5000.00", "currency": "USD", "account": "acct_1",
	})
	errObject := AsMap(response["error"])
	if intValue(errObject["code"]) != -32000 {
		t.Fatalf("unexpected error: %+v", response)
	}
	if stringField(AsMap(errObject["data"]), "receipt_id") == "" {
		t.Fatal("denial did not carry a receipt id")
	}
	if atomic.LoadInt64(calls) != 0 {
		t.Fatal("denied call reached downstream")
	}
	if result := stringValue(wrapper.ledger.Receipts[0].Decision["result"]); result != "denied" {
		t.Fatalf("denial receipt result: %s", result)
	}
}

func TestMCPWrapperHonorsStatusRevocation(t *testing.T) {
	signer, pub := newSigner(t, "mcp_status_signer")
	token, err := BuildStatusToken("https://example.invalid/status", []int{0x01},
		signer, 1800000000, 1800000600, 300)
	if err != nil {
		t.Fatal(err)
	}
	idx := 0
	wrapper, calls, _ := mcpTestWrapper(t, token, signer.PublicKeys(), &idx)
	_ = pub
	response := callRPC(wrapper, 3, map[string]any{
		"amount": "100.00", "currency": "USD", "account": "acct_1",
	})
	if AsMap(response["error"]) == nil || atomic.LoadInt64(calls) != 0 {
		t.Fatalf("revoked delegation was allowed: %+v", response)
	}
}

func TestMCPWrapperUnknownTool(t *testing.T) {
	wrapper, _, _ := mcpTestWrapper(t, "", nil, nil)
	request, _ := DecodeJSON(MCPRequestJSON(4, "not_a_tool", map[string]any{}))
	response := wrapper.HandleRPC(context.Background(), AsMap(request))
	if intValue(AsMap(response["error"])["code"]) != -32601 {
		t.Fatalf("unknown tool was not rejected: %+v", response)
	}
}

func TestMCPHandlerMountsWrapper(t *testing.T) {
	wrapper, _, _ := mcpTestWrapper(t, "", nil, nil)
	handler := NewMCPHandler(wrapper)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/mcp",
			strings.NewReader(string(MCPRequestJSON(5, "purchase_ad_credit", map[string]any{
				"amount": "100.00", "currency": "USD", "account": "acct_1",
			})))))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "receipt_id") {
		t.Fatalf("MCP handler failed: %d %s", recorder.Code, recorder.Body.String())
	}
}
