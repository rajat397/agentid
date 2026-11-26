package agentid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/rajat397/agentid/attest"
)

type QuickstartResult struct {
	FirstReceipt           string
	DeniedReceipt          string
	BundlePath             string
	Verified               bool
	BlockedCalls           int32
	DownstreamCallsDenied  int32
	DownstreamCallsAllowed int32
	Elapsed                time.Duration
}

func RunQuickstart(outDir, credentialEnv string) (*QuickstartResult, error) {
	started := time.Now()
	if credentialEnv == "" {
		credentialEnv = "AGENTID_QUICKSTART_TOKEN"
	}
	if os.Getenv(credentialEnv) == "" {
		if err := os.Setenv(credentialEnv, "quickstart-local-token"); err != nil {
			return nil, err
		}
	}
	credential := os.Getenv(credentialEnv)

	var deniedCalls, allowedCalls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request := AsMap(mustDecodeJSON(body))
		if stringField(request, "amount") == "4500.00" {
			deniedCalls.Add(1)
		} else {
			allowedCalls.Add(1)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "accepted", "order_id": "quickstart_order",
		})
	}))
	defer downstream.Close()

	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	signer, err := NewDevSigner(privatePEM, publicPEM, "quickstart_signer")
	if err != nil {
		return nil, err
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "quickstart|operator"},
		"quickstart-agent",
		map[string]any{
			"permissions":                   []any{map[string]any{"action": "ad.credit.purchase", "system": "meta-ads"}},
			"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
			"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
		},
		dateTimeNow().Add(30*time.Minute).Format(timeLayout),
		DelegationOptions{
			Signer: signer,
			Attestor: attest.DevAttestor{
				SPIFFEID:  "spiffe://quickstart/agent",
				PublicKey: publicPEM,
			},
		})
	if err != nil {
		return nil, err
	}

	reviewerPrivate, reviewerPublic, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	reviewer, err := NewDevSigner(reviewerPrivate, reviewerPublic, "quickstart_reviewer")
	if err != nil {
		return nil, err
	}
	approval, err := SignApproval(map[string]any{
		"id":           "apr_quickstart",
		"delegation_id": delegation.ID,
		"action":       "ad.credit.purchase",
		"amount":       "2000.00",
		"approver":     "quickstart|operator",
		"nonce":        "quickstart-nonce",
	}, reviewer)
	if err != nil {
		return nil, err
	}

	wrapper, err := NewMCPWrapper(MCPWrapperConfig{
		Mode: OperatorModeEnforce,
		Tools: []ToolMapping{{
			Name:             "purchase_ad_credit",
			Action:           "ad.credit.purchase",
			System:           "meta-ads",
			ResourceType:     "ad_credit_account",
			AllowedArgs:      []string{"amount", "currency"},
			Stage:            StageSideEffect,
			Provenance:       ProvenanceTrusted,
			SensitivityTier:  "confidential",
			DownstreamURL:    downstream.URL,
			DownstreamMethod: http.MethodPost,
			CredentialEnv:    credentialEnv,
		}},
		Chain:      []Delegation{delegation},
		Profile:    ExampleProfile(),
		RootKeyPEM: publicPEM,
		Signer:     signer,
		Approval:   approval,
	})
	if err != nil {
		return nil, err
	}
	wrapper.SetAuthToken("quickstart-mcp-token")

	mcp := httptest.NewServer(NewMCPHandler(wrapper))
	defer mcp.Close()

	call := func(id int, amount string) map[string]any {
		request := MCPRequestJSON(id, "purchase_ad_credit", map[string]any{
			"amount": amount, "currency": "USD",
		})
		req, err := http.NewRequest(http.MethodPost, mcp.URL, bytes.NewReader(request))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer quickstart-mcp-token")
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		return AsMap(mustDecodeJSON(body))
	}

	denied := call(1, "4500.00")
	blockedCalls := int32(0)
	if AsMap(denied["error"]) != nil {
		blockedCalls = 1
	}
	deniedReceipt := stringField(AsMap(AsMap(denied["error"])["data"]), "receipt_id")
	allowed := call(2, "2000.00")
	allowedReceipt := stringField(AsMap(AsMap(allowed["result"])["_meta"]), "receipt_id")
	if deniedReceipt == "" || allowedReceipt == "" {
		deniedJSON, _ := json.Marshal(denied)
		allowedJSON, _ := json.Marshal(allowed)
		return nil, fmt.Errorf("quickstart missing receipts: denied=%s allowed=%s", deniedJSON, allowedJSON)
	}

	if err := os.MkdirAll(outDir, 0700); err != nil {
		return nil, err
	}
	bundle, err := BuildEvidenceBundle("quickstart", wrapper.Ledger(),
		[]Delegation{delegation}, ExampleProfile(), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	data, err := CanonicalJSON(bundle.ToMap())
	if err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(outDir, "quickstart-bundle.json")
	if err := os.WriteFile(bundlePath, data, 0600); err != nil {
		return nil, err
	}

	verified := true
	for _, receipt := range bundle.Receipts {
		if !VerifyReceiptExternal(ReceiptFromMap(receipt), bundle.SignerKeys).Verified {
			verified = false
			break
		}
	}

	return &QuickstartResult{
		FirstReceipt:           allowedReceipt,
		DeniedReceipt:          deniedReceipt,
		BundlePath:             bundlePath,
		Verified:               verified,
		BlockedCalls:           blockedCalls,
		DownstreamCallsDenied:  deniedCalls.Load(),
		DownstreamCallsAllowed: allowedCalls.Load(),
		Elapsed:                time.Since(started),
	}, nil
}

func mustDecodeJSON(data []byte) any {
	value, err := DecodeJSON(data)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	return value
}

