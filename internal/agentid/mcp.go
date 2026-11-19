package agentid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"encoding/base64"
	"strings"
)

// ToolMapping is operator-owned configuration. Authority fields come from the
// mapping, never from the agent's tool arguments.
type ToolMapping struct {
	Name             string   `json:"name"`
	Action           string   `json:"action"`
	System           string   `json:"system"`
	ResourceType     string   `json:"resource_type"`
	ResourceIDField  string   `json:"resource_id_field"`
	AllowedArgs      []string `json:"allowed_args"`
	Stage            string   `json:"stage"`
	Provenance       string   `json:"provenance"`
	SensitivityTier  string   `json:"sensitivity_tier"`
	BudgetKey        string   `json:"budget_key"`
	DownstreamURL    string   `json:"downstream_url"`
	DownstreamMethod string   `json:"downstream_method"`
	CredentialEnv    string   `json:"credential_env"`
}

// MCPWrapperConfig supplies the evidence and policy inputs to the wrapper.
type MCPWrapperConfig struct {
	Tools       []ToolMapping
	Chain       []Delegation
	Profile     Profile
	RootKeyPEM  []byte
	Signer      Signer
	Fleet       string
	StatusToken string
	StatusKeys  map[string]string
	Approval    map[string]any
	Ledger      *Ledger
}

// MCPWrapper is the policy enforcement point for an MCP tool surface.
type MCPWrapper struct {
	config       MCPWrapperConfig
	ledger       *Ledger
	statusLookup func(uri string, idx int) (int, error)
	httpClient   *http.Client
	mu           sync.RWMutex
}

// NewMCPWrapper validates configuration and installs fail-closed revocation
// lookup when the leaf delegation carries a status list.
func NewMCPWrapper(config MCPWrapperConfig) (*MCPWrapper, error) {
	if len(config.Chain) == 0 || len(config.RootKeyPEM) == 0 {
		return nil, errors.New("MCP wrapper needs a delegation chain and root key")
	}
	if config.Signer == nil {
		return nil, errors.New("MCP wrapper needs a signer for receipts")
	}
	ledger := config.Ledger
	if ledger == nil {
		ledger = &Ledger{}
	}
	wrapper := &MCPWrapper{config: config, ledger: ledger,
		httpClient: &http.Client{}}
	if config.StatusToken != "" {
		if len(config.StatusKeys) == 0 {
			return nil, errors.New("status token supplied without signing keys")
		}
		token := config.StatusToken
		keys := config.StatusKeys
		wrapper.statusLookup = func(uri string, idx int) (int, error) {
			return CheckStatus(token, idx, keys, config.Profile.MaxStatusAge, 0)
		}
		// Validate the token once at startup; stale tokens fail closed here.
		if _, err := VerifyStatusTokenAtIssuedTime(token, keys,
			config.Profile.MaxStatusAge); err != nil {
			return nil, fmt.Errorf("status token unusable: %w", err)
		}
		wrapper.statusLookup = func(uri string, idx int) (int, error) {
			return checkStatusAtIssuedTime(token, idx, keys, config.Profile.MaxStatusAge)
		}
	}
	return wrapper, nil
}

func checkStatusAtIssuedTime(token string, idx int, keys map[string]string, maxAge int) (int, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return 0, errors.New("malformed status token")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, err
	}
	payload, err := DecodeJSON(payloadJSON)
	if err != nil {
		return 0, err
	}
	return CheckStatus(token, idx, keys, maxAge, intValue(AsMap(payload)["iat"]))
}

// HandleRPC handles one JSON-RPC 2.0 request. Only tools/call reaches the
// downstream service; tools/list advertises names without credentials.
func (w *MCPWrapper) HandleRPC(ctx context.Context, request map[string]any) map[string]any {
	id := request["id"]
	method := stringField(request, "method")
	if method != "tools/call" && method != "tools/list" {
		return rpcError(id, -32601, "method not found: "+method, "")
	}
	if method == "tools/list" {
		tools := []any{}
		for _, tool := range w.config.Tools {
			tools = append(tools, map[string]any{"name": tool.Name, "description": "gated by agentid"})
		}
		return map[string]any{"jsonrpc": "2.0", "id": id,
			"result": map[string]any{"tools": tools}}
	}
	params := AsMap(request["params"])
	name := stringField(params, "name")
	mapping, ok := w.tool(name)
	if !ok {
		return rpcError(id, -32601, "unknown tool: "+name, "")
	}
	action, err := w.actionFrom(mapping, AsMap(params["arguments"]))
	if err != nil {
		return rpcError(id, -32602, "invalid arguments: "+err.Error(), "")
	}
	statusLookup := w.currentStatusLookup()
	_, result, err := Act(w.ledger, w.config.Chain, action, w.config.Profile,
		w.config.RootKeyPEM, ActOptions{
			Fleet: w.config.Fleet, Signer: w.config.Signer,
			Approval: w.config.Approval, StatusLookup: statusLookup,
		})
	if err != nil {
		return rpcError(id, -32000, "receipt failed: "+err.Error(), "")
	}
	receipt := w.ledger.Receipts[len(w.ledger.Receipts)-1]
	if result.Outcome != "valid" {
		return rpcError(id, -32000, "blocked: "+result.Reason, receipt.ID)
	}
	credential := os.Getenv(mapping.CredentialEnv)
	if credential == "" {
		return rpcError(id, -32000, "downstream credential is not configured", receipt.ID)
	}
	responseBody, err := w.callDownstream(ctx, mapping, action, credential)
	if err != nil {
		return rpcError(id, -32000, "downstream call failed", receipt.ID)
	}
	return map[string]any{
		"jsonrpc": "2.0", "id": id,
		"result": map[string]any{
			"content": []any{map[string]any{"type": "text", "text": responseBody}},
			"_meta":   map[string]any{"receipt_id": receipt.ID},
		},
	}
}

func (w *MCPWrapper) tool(name string) (ToolMapping, bool) {
	for _, tool := range w.config.Tools {
		if tool.Name == name {
			return tool, true
		}
	}
	return ToolMapping{}, false
}

func (w *MCPWrapper) actionFrom(mapping ToolMapping, arguments map[string]any) (map[string]any, error) {
	action := map[string]any{
		"action": mapping.Action, "system": mapping.System,
		"resource_type": mapping.ResourceType,
	}
	if mapping.ResourceIDField != "" {
		action["resource_id"] = arguments[mapping.ResourceIDField]
	}
	for _, key := range mapping.AllowedArgs {
		if value, ok := arguments[key]; ok {
			action[key] = value
		}
	}
	// Authority fields are always overwritten from operator configuration.
	action["stage"] = mapping.Stage
	if mapping.Provenance != "" {
		action["provenance"] = mapping.Provenance
	}
	if mapping.SensitivityTier != "" {
		action["sensitivity_tier"] = mapping.SensitivityTier
	}
	if mapping.BudgetKey != "" {
		action["budget_key"] = mapping.BudgetKey
	}
	if mapping.Action == "" || mapping.System == "" {
		return nil, errors.New("tool mapping is missing action or system")
	}
	return action, nil
}

func (w *MCPWrapper) callDownstream(ctx context.Context, mapping ToolMapping,
	action map[string]any, credential string) (string, error) {
	method := mapping.DownstreamMethod
	if method == "" {
		method = http.MethodPost
	}
	payload, err := CanonicalJSON(action)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, method, mapping.DownstreamURL,
		bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	response, err := w.httpClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("downstream HTTP %d", response.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}

func rpcError(id any, code int, message, receiptID string) map[string]any {
	data := map[string]any{}
	if receiptID != "" {
		data["receipt_id"] = receiptID
	}
	return map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": message, "data": data},
	}
}

// NewMCPHandler mounts the wrapper as a JSON-RPC HTTP endpoint.
func NewMCPHandler(wrapper *MCPWrapper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcError(nil, -32700, "read error", ""))
			return
		}
		value, err := DecodeJSON(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, rpcError(nil, -32700, "parse error", ""))
			return
		}
		writeJSON(w, http.StatusOK, wrapper.HandleRPC(r.Context(), AsMap(value)))
	})
}

// MockMetaAdsHandler is the local reference downstream tool: it accepts only
// the configured credential and reports an order id.
func MockMetaAdsHandler(credential string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"order_id": "mock_order_1", "status": "accepted",
		})
	})
}

// MCPRequestJSON builds a tools/call JSON-RPC request for tests and demos.
func MCPRequestJSON(id int, tool string, arguments map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	return data
}

// MCPConfigFile is the on-disk configuration. Credentials are referenced by
// environment-variable name only; no secret is ever stored in this file.
type MCPConfigFile struct {
	Tools       []ToolMapping `json:"tools"`
	Delegations string        `json:"delegations"`
	Profile     string        `json:"profile"`
	RootKey     string        `json:"root_key"`
	SignerKey   string        `json:"signer_key"`
	StatusToken string        `json:"status_token"`
	StatusKeys  string        `json:"status_keys"`
	Approval    string        `json:"approval"`
	Fleet       string        `json:"fleet"`
}

func readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(path)
}

// LoadMCPWrapper builds a wrapper from a configuration file.
func LoadMCPWrapper(path string) (*MCPWrapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file MCPConfigFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	config := MCPWrapperConfig{Tools: file.Tools, Fleet: file.Fleet}

	delegationData, err := os.ReadFile(file.Delegations)
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(delegationData), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		value, err := DecodeJSON([]byte(line))
		if err != nil {
			return nil, err
		}
		delegation, err := DelegationFromMap(AsMap(value))
		if err != nil {
			return nil, err
		}
		config.Chain = append(config.Chain, delegation)
	}
	config.RootKeyPEM, err = os.ReadFile(file.RootKey)
	if err != nil {
		return nil, err
	}
	profileData, err := os.ReadFile(file.Profile)
	if err != nil {
		return nil, err
	}
	profileValue, err := DecodeJSON(profileData)
	if err != nil {
		return nil, err
	}
	config.Profile, err = ProfileFromMap(AsMap(profileValue))
	if err != nil {
		return nil, err
	}
	signerData, err := os.ReadFile(file.SignerKey)
	if err != nil {
		return nil, err
	}
	privateKey, err := ParsePrivatePEM(signerData)
	if err != nil {
		return nil, err
	}
	publicPEM, err := PublicPEMFromPrivate(privateKey)
	if err != nil {
		return nil, err
	}
	config.Signer, err = NewDevSigner(signerData, publicPEM, "mcp_signer")
	if err != nil {
		return nil, err
	}
	if tokenData, err := readOptional(file.StatusToken); err != nil {
		return nil, err
	} else if tokenData != nil {
		config.StatusToken = strings.TrimSpace(string(tokenData))
	}
	if keysData, err := readOptional(file.StatusKeys); err != nil {
		return nil, err
	} else if keysData != nil {
		value, err := DecodeJSON(keysData)
		if err != nil {
			return nil, err
		}
		config.StatusKeys = map[string]string{}
		for kid, material := range AsMap(value) {
			config.StatusKeys[kid] = stringValue(material)
		}
	}
	if approvalData, err := readOptional(file.Approval); err != nil {
		return nil, err
	} else if approvalData != nil {
		value, err := DecodeJSON(approvalData)
		if err != nil {
			return nil, err
		}
		config.Approval = AsMap(value)
	}
	return NewMCPWrapper(config)
}

func (w *MCPWrapper) currentStatusLookup() func(string, int) (int, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.statusLookup
}

// RefreshStatus atomically swaps the PEP's status token. A stale or malformed
// token is rejected without disturbing the running lookup.
func (w *MCPWrapper) RefreshStatus(token string, keys map[string]string, maxAge int) error {
	if _, err := VerifyStatusTokenAtIssuedTime(token, keys, maxAge); err != nil {
		return err
	}
	lookup := func(uri string, idx int) (int, error) {
		return checkStatusAtIssuedTime(token, idx, keys, maxAge)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.statusLookup = lookup
	return nil
}
