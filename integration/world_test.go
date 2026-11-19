package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rajat397/agentid/attest"
	"github.com/rajat397/agentid/internal/agentid"
)

// World is an isolated, in-process deployment used by real-world scenarios.
// Every dependency is a local fixture: no network, no cloud, no shared state.
type World struct {
	t           *testing.T
	signer      *agentid.DevSigner
	rootPub     []byte
	delegation  agentid.Delegation
	profile     agentid.Profile
	statusToken string
	statusKeys  map[string]string
	statuses    []int
	wrapper     *agentid.MCPWrapper
	adsCalls    *int64
	scimActive  *atomic.Bool
	scimClient  agentid.SCIMClient
	registry    *agentid.FileRegistry
	publisher   agentid.StatusPublisher
	ledgerPath  string
}

func NewWorld(t *testing.T) *World {
	t.Helper()
	credential := "integration-mock-credential"
	t.Setenv("MOCK_ADS_CREDENTIAL", credential)

	var adsCalls int64
	ads := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&adsCalls, 1)
		if r.Header.Get("Authorization") != "Bearer "+credential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"order_id": "integration_order", "status": "accepted"})
	}))
	t.Cleanup(ads.Close)

	active := atomic.Bool{}
	active.Store(true)
	scim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		state := active.Load()
		json.NewEncoder(w).Encode(map[string]any{
			"totalResults": 1,
			"Resources": []any{map[string]any{
				"id": "usr_8842", "userName": "alice@example.com", "active": state,
				"groups": []any{map[string]any{"value": "agents", "display": "agents"}},
			}},
		})
	}))
	t.Cleanup(scim.Close)
	scimClient := agentid.SCIMClient{BaseURL: scim.URL}

	privatePEM, publicPEM, err := agentid.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentid.NewDevSigner(privatePEM, publicPEM, "integration_key")
	if err != nil {
		t.Fatal(err)
	}
	subject := map[string]any{"type": "human", "id": "usr_8842"}
	idx := 0
	delegation, err := agentid.CreateDelegation(nil, subject, "marketing-agent", map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"max_amount": map[string]any{"value": "2000.00", "currency": "USD"},
	}, "2030-01-01T00:00:00Z", agentid.DelegationOptions{
		Signer: signer, StatusIdx: &idx,
		Attestor: attest.DevAttestor{
			SPIFFEID:  "spiffe://example.trust/agent/marketing-agent",
			PublicKey: publicPEM,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := agentid.ExampleProfile()
	registry, err := agentid.OpenFileRegistry(t.TempDir() + "/registry.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("usr_8842", delegation.ID, 0); err != nil {
		t.Fatal(err)
	}
	publisher := agentid.StatusPublisher{
		Registry: registry, Signer: signer,
		URI: "https://example.invalid/status", TTL: 300,
		MaxAge: profile.MaxStatusAge,
	}
	token, err := publisher.Publish()
	if err != nil {
		t.Fatal(err)
	}
	statuses := []int{0x00}
	mapping := agentid.ToolMapping{
		Name: "purchase_ad_credit", Action: "ad.credit.purchase", System: "meta-ads",
		ResourceType: "ad_credit_account", AllowedArgs: []string{"amount", "currency"},
		Stage: agentid.StageSideEffect, Provenance: agentid.ProvenanceTrusted,
		DownstreamURL: ads.URL, CredentialEnv: "MOCK_ADS_CREDENTIAL",
	}
	wrapper, err := agentid.NewMCPWrapper(agentid.MCPWrapperConfig{
		Tools: []agentid.ToolMapping{mapping}, Chain: []agentid.Delegation{delegation},
		Profile: profile, RootKeyPEM: publicPEM, Signer: signer,
		Fleet: "integration", StatusToken: token, StatusKeys: signer.PublicKeys(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &World{
		t: t, signer: signer, rootPub: publicPEM, delegation: delegation,
		profile: profile, statusToken: token, statusKeys: signer.PublicKeys(),
		statuses: statuses, wrapper: wrapper, adsCalls: &adsCalls,
		registry: registry, publisher: publisher,
		scimActive: &active, scimClient: scimClient,
		ledgerPath: t.TempDir() + "/ledger.jsonl",
	}
}

func (w *World) callTool(amount string) map[string]any {
	w.t.Helper()
	value, err := agentid.DecodeJSON(agentid.MCPRequestJSON(1, "purchase_ad_credit",
		map[string]any{"amount": amount, "currency": "USD"}))
	if err != nil {
		w.t.Fatal(err)
	}
	return w.wrapper.HandleRPC(context.Background(), agentid.AsMap(value))
}

func (w *World) expectAllowed(response map[string]any) {
	w.t.Helper()
	if agentid.AsMap(response["error"]) != nil {
		w.t.Fatalf("expected allow, got %+v", response)
	}
}

func (w *World) expectDenied(response map[string]any) {
	w.t.Helper()
	errObject := agentid.AsMap(response["error"])
	if errObject == nil || agentid.IntValue(errObject["code"]) != -32000 {
		w.t.Fatalf("expected deny, got %+v", response)
	}
}

// Deprovision runs a real SCIM read against the fixture directory and computes
// the revocation delta. Publishing the delta is D26's missing link.
func (w *World) Deprovision() {
	w.t.Helper()
	// The SCIM server URL is captured in the wrapper-independent client below.
	client := w.scimClient
	users, err := client.FetchUsers(context.Background())
	if err != nil {
		w.t.Fatal(err)
	}
	previous := map[string]bool{"usr_8842": true}
	revoked, _ := agentid.SCIMRevocations(users, "agents", previous)
	for _, subject := range revoked {
		if err := w.registry.Revoke(subject); err != nil {
			w.t.Fatal(err)
		}
	}
}

func (w *World) PublishStatusToken() {
	w.t.Helper()
	token, err := agentid.BuildStatusToken("https://example.invalid/status", w.statuses,
		w.signer, 1800000000, 1800000600, 300)
	if err != nil {
		w.t.Fatal(err)
	}
	w.statusToken = token
}

func (w *World) AssertStatus(expected int) {
	w.t.Helper()
	status, err := agentid.CheckStatusAtIssuedTime(w.statusToken, 0,
		w.statusKeys, w.profile.MaxStatusAge)
	if err != nil {
		w.t.Fatal(err)
	}
	if status != expected {
		w.t.Fatalf("status = 0x%02x, want 0x%02x", status, expected)
	}
}

func (w *World) RefreshWrapper() {
	w.t.Helper()
	token, err := w.publisher.Publish()
	if err != nil {
		w.t.Fatal(err)
	}
	w.statusToken = token
	if err := w.wrapper.RefreshStatus(token, w.statusKeys, w.profile.MaxStatusAge); err != nil {
		w.t.Fatal(err)
	}
}
