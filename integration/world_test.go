package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rajat397/agentid/attest"
	"github.com/rajat397/agentid/internal/agentid"
)

// World is an isolated, in-process deployment used by real-world scenarios.
// Every dependency is a local fixture: no network, no cloud, no shared state.
type World struct {
	t               *testing.T
	signer          *agentid.DevSigner
	rootPub         []byte
	delegation      agentid.Delegation
	profile         agentid.Profile
	statusToken     string
	statusKeys      map[string]string
	statuses        []int
	wrapper         *agentid.MCPWrapper
	adsCalls        *int64
	scimActive      *atomic.Bool
	tsaURL          string
	tsaCalls        *int64
	bucketDir       string
	bucketSigner    agentid.Signer
	bucketStamps    []map[string]any
	retentionDir    string
	archivePath     string
	archiveReceipt  *agentid.Receipt
	tombstones      []string
	zendesk         *mockDownstream
	crm             *mockDownstream
	erasureReceipts []*agentid.Receipt
	erasureError    error
	verifyProblems  []string
	evidenceSpans   []map[string]any
	spanProblems    []string
	spanTraceID     string
	trace           agentid.TraceContext
	controlPlane    bool
	cp              *agentid.ControlPlane
	cache           *agentid.PolicyCache
	intent          agentid.IntentCompilation
	anchorMgr       interface {
		Observe(*agentid.Ledger, string) ([]map[string]any, error)
	}
	scimClient  agentid.SCIMClient
	registry    *agentid.FileRegistry
	publisher   agentid.StatusPublisher
	anchors     []map[string]any
	mockTSAFail *atomic.Bool
	ledger      *agentid.Ledger
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
	worldLedger := &agentid.Ledger{}
	var tsaCalls int64
	tsaFail := atomic.Bool{}
	tsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tsaCalls, 1)
		if tsaFail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		_ = body
		ledgerHead := "0"
		if head, err := agentid.ChainHead(worldLedger); err == nil {
			ledgerHead = head
		}
		response, err := agentid.BuildMockTimestampResponse(ledgerHead,
			"20261120000000Z", 12345)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write(response)
	}))
	t.Cleanup(tsa.Close)

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
	trace, err := agentid.NewTraceContext()
	if err != nil {
		t.Fatal(err)
	}
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
		ResourceType: "ad_credit_account",
		AllowedArgs:  []string{"amount", "currency", "personal_data_refs"},
		Stage:        agentid.StageSideEffect, Provenance: agentid.ProvenanceTrusted,
		DownstreamURL: ads.URL, CredentialEnv: "MOCK_ADS_CREDENTIAL",
	}
	wrapper, err := agentid.NewMCPWrapper(agentid.MCPWrapperConfig{
		Tools: []agentid.ToolMapping{mapping}, Chain: []agentid.Delegation{delegation},
		Profile: profile, RootKeyPEM: publicPEM, Signer: signer,
		Fleet: "integration", StatusToken: token, StatusKeys: signer.PublicKeys(),
		Trace: &trace,
	})
	if err != nil {
		t.Fatal(err)
	}
	worldLedger = wrapper.Ledger()
	manager, err := agentid.NewAnchorManager(agentid.AnchorConfig{
		TSAURL: tsa.URL, StrictCA: true,
		Cadence: agentid.AnchorCadence{MaxReceipts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := agentid.NewControlPlane(signer, registry, publisher, manager)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.PublishPolicy(profile); err != nil {
		t.Fatal(err)
	}
	bundle, err := cp.PolicyBundle()
	if err != nil {
		t.Fatal(err)
	}
	cache := agentid.NewPolicyCache(signer.PublicKeys(), 5*time.Minute)
	if err := cache.Refresh(bundle); err != nil {
		t.Fatal(err)
	}
	wrapper.SetPolicyProvider(cache.Profile)
	return &World{
		t: t, signer: signer, rootPub: publicPEM, delegation: delegation,
		profile: profile, statusToken: token, statusKeys: signer.PublicKeys(),
		statuses: statuses, wrapper: wrapper, adsCalls: &adsCalls,
		registry: registry, publisher: publisher,
		scimActive: &active, scimClient: scimClient,
		anchorMgr: manager, tsaURL: tsa.URL, tsaCalls: &tsaCalls,
		mockTSAFail: &tsaFail, bucketDir: t.TempDir(), bucketSigner: signer,
		retentionDir: t.TempDir(),
		ledger:       worldLedger, ledgerPath: t.TempDir() + "/ledger.jsonl",
		cp: cp, cache: cache, controlPlane: true,
	}
}

func (w *World) callTool(amount string) map[string]any {
	w.t.Helper()
	value, err := agentid.DecodeJSON(agentid.MCPRequestJSON(1, "purchase_ad_credit",
		map[string]any{"amount": amount, "currency": "USD",
			"personal_data_refs": []any{"cust_4471"}}))
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

func (w *World) ObserveAnchors() {
	w.t.Helper()
	anchors, err := w.anchorMgr.Observe(w.ledger, w.tsaURL)
	if err != nil {
		w.t.Fatal(err)
	}
	w.anchors = anchors
}

func (w *World) FailTSA() { w.mockTSAFail.Store(true) }
func (w *World) FixTSA()  { w.mockTSAFail.Store(false) }

func (w *World) DetectGaps(anchors []map[string]any) []string {
	return agentid.DetectAnchorGaps(anchors, w.ledger)
}

func (w *World) VerifyAuditBundle() {
	w.t.Helper()
	bundle, err := agentid.BuildEvidenceBundle("integration", w.ledger,
		[]agentid.Delegation{w.delegation}, w.profile, w.anchors, nil,
		w.signer.PublicKeys())
	if err != nil {
		w.t.Fatal(err)
	}
	if problems := agentid.VerifyEvidenceBundle(bundle); len(problems) > 0 {
		w.t.Fatalf("auditor bundle failed: %v", problems)
	}
}

func (w *World) ObserveBucketAnchors() {
	w.t.Helper()
	head, err := agentid.ChainHead(w.ledger)
	if err != nil {
		w.t.Fatal(err)
	}
	stamp, err := agentid.NewBucketStamp(head, len(w.ledger.Receipts)-1, w.bucketSigner)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := agentid.WriteBucketStamp(w.bucketDir, stamp); err != nil {
		w.t.Fatal(err)
	}
	data, err := agentid.CanonicalJSON(stamp)
	if err != nil {
		w.t.Fatal(err)
	}
	value, err := agentid.DecodeJSON(data)
	if err != nil {
		w.t.Fatal(err)
	}
	w.bucketStamps = append(w.bucketStamps, agentid.AsMap(value))
}

func (w *World) VerifyBucketStamp(raw map[string]any) []string {
	w.t.Helper()
	head, err := agentid.ChainHead(w.ledger)
	if err != nil {
		w.t.Fatal(err)
	}
	return agentid.VerifyBucketStamp(
		agentid.BucketStampFromMap(raw), w.bucketSigner.PublicKeys(), head)
}

func (w *World) ExportRetention() {
	w.t.Helper()
	at := time.Now().AddDate(0, 14, 0)
	path, receipt, err := agentid.ExportArchive(w.ledger, agentid.RetentionPolicy{
		WindowMonths: agentid.DefaultRetentionMonths, ArchiveDir: w.retentionDir,
	}, at)
	if err != nil {
		w.t.Fatal(err)
	}
	w.archivePath = path
	w.archiveReceipt = receipt
}

func (w *World) TombstoneSubject() {
	w.t.Helper()
	receipt, err := agentid.Tombstone(w.ledger, "cust_4471", time.Now())
	if err != nil {
		w.t.Fatal(err)
	}
	attributes := agentid.AsMap(agentid.AsMap(receipt.Resource)["attributes"])
	for _, target := range agentid.AsSlice(attributes["targets"]) {
		w.tombstones = append(w.tombstones, agentid.StringValue(target))
	}
}

func (w *World) ArchiveProblem() []string {
	w.t.Helper()
	return agentid.VerifyArchive(w.archivePath, w.archiveReceipt)
}

type mockDownstream struct {
	system  string
	records map[string]bool
	fail    bool
	url     string
}

func (m *mockDownstream) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/subjects/")
		if r.Method == http.MethodDelete {
			if !m.records[ref] {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(m.records, ref)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if m.records[ref] {
			json.NewEncoder(w).Encode(map[string]any{"found": true})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func (w *World) erasureConnectors() []agentid.DownstreamConnector {
	w.t.Helper()
	for _, system := range []*mockDownstream{w.zendesk, w.crm} {
		if system.url == "" {
			server := httptest.NewServer(system.handler())
			w.t.Cleanup(server.Close)
			system.url = server.URL
		}
	}
	return []agentid.DownstreamConnector{
		agentid.HTTPConnector{SystemName: w.zendesk.system,
			BaseURL: w.zendesk.url, Credential: "mock-credential"},
		agentid.HTTPConnector{SystemName: w.crm.system,
			BaseURL: w.crm.url, Credential: "mock-credential"},
	}
}

func (w *World) ErasureExec() {
	w.t.Helper()
	receipts, err := agentid.ExecuteErasure(w.ledger, "ers_1", "cust_4471",
		w.erasureConnectors(), time.Now())
	w.erasureReceipts = append(w.erasureReceipts, receipts...)
	w.erasureError = err
}

func (w *World) ErasureVerify() {
	w.t.Helper()
	w.verifyProblems = agentid.VerifyErasure(w.erasureConnectors(), "cust_4471")
}

func (w *World) EvidenceSpans() {
	w.t.Helper()
	receipt := w.ledger.Receipts[0]
	trace := agentid.TraceContext{
		TraceID: agentid.StringValue(receipt.Decision["trace_id"]),
		SpanID:  agentid.StringValue(receipt.Decision["span_id"]),
	}
	w.trace = trace
	w.spanTraceID = trace.TraceID
	w.evidenceSpans = agentid.BuildEvidenceSpans(receipt, w.delegation, trace, false)
}

func mismatchStrings(mismatches []agentid.Mismatch) []string {
	out := []string{}
	for _, mismatch := range mismatches {
		out = append(out, mismatch.Type+":"+mismatch.Detail)
	}
	return out
}

func (w *World) SpanProblems() []string {
	w.t.Helper()
	return mismatchStrings(agentid.ReconcileEvidenceSpans(w.evidenceSpans, w.ledger))
}

func spanSetJSON(spans []map[string]any) string {
	data, _ := json.Marshal(spans)
	return string(data)
}

func (w *World) SpanProblemsFor(spans []map[string]any) []string {
	w.t.Helper()
	return mismatchStrings(agentid.ReconcileEvidenceSpans(spans, w.ledger))
}

func (w *World) PublishPolicyChange() {
	w.t.Helper()
	document := agentid.ExampleProfile().Document()
	document["stage_allowlist"] = []any{agentid.StagePlan}
	profile, err := agentid.ProfileFromMap(document)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.cp.PublishPolicy(profile); err != nil {
		w.t.Fatal(err)
	}
}

func (w *World) RefreshPEP() {
	w.t.Helper()
	if !w.controlPlane {
		w.cache.Expire()
		return
	}
	bundle, err := w.cp.PolicyBundle()
	if err != nil {
		w.t.Fatal(err)
	}
	if err := w.cache.Refresh(bundle); err != nil {
		w.t.Fatal(err)
	}
}

func (w *World) TypedCall(args map[string]any, typeProfile map[string]any) map[string]any {
	w.t.Helper()
	privatePEM, publicPEM, err := agentid.GenerateKeyPair()
	if err != nil {
		w.t.Fatal(err)
	}
	signer, err := agentid.NewDevSigner(privatePEM, publicPEM, "typed_key")
	if err != nil {
		w.t.Fatal(err)
	}
	constraints := map[string]any{
		"permissions": []any{map[string]any{"action": "typed.action", "system": "typed"}},
	}
	if _, ok := args["rows"]; ok {
		constraints["predicates"] = []any{map[string]any{
			"type": "max", "path": "/attributes/rows", "value": "100",
		}}
	}
	if _, ok := args["priority"]; ok {
		constraints["predicates"] = []any{map[string]any{
			"type": "in", "path": "/attributes/priority", "values": []any{"low", "high"},
		}}
	}
	delegation, err := agentid.CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "typed-agent", constraints,
		"2030-01-01T00:00:00Z", agentid.DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		w.t.Fatal(err)
	}
	document := agentid.ExampleProfile().Document()
	document["type_profile"] = typeProfile
	profile, err := agentid.ProfileFromMap(document)
	if err != nil {
		w.t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	w.t.Cleanup(server.Close)
	w.t.Setenv("TYPED_CREDENTIAL", "typed-secret")
	mapping := agentid.ToolMapping{
		Name: "typed.tool", Action: "typed.action", System: "typed",
		AllowedArgs:   []string{"rows", "priority"},
		DownstreamURL: server.URL, CredentialEnv: "TYPED_CREDENTIAL",
	}
	wrapper, err := agentid.NewMCPWrapper(agentid.MCPWrapperConfig{
		Tools: []agentid.ToolMapping{mapping}, Chain: []agentid.Delegation{delegation},
		Profile: profile, RootKeyPEM: publicPEM, Signer: signer,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	request, _ := agentid.DecodeJSON(agentid.MCPRequestJSON(1, "typed.tool", args))
	return wrapper.HandleRPC(context.Background(), agentid.AsMap(request))
}

func (w *World) callWithDelegation(delegation agentid.Delegation,
	pub []byte, signer agentid.Signer) map[string]any {
	w.t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	w.t.Cleanup(server.Close)
	w.t.Setenv("INTENT_CREDENTIAL", "intent-secret")
	mapping := agentid.ToolMapping{
		Name: "intent.tool", Action: "ad.credit.purchase", System: "meta-ads",
		ResourceType:  "ad_credit_account",
		AllowedArgs:   []string{"amount", "currency", "region"},
		DownstreamURL: server.URL, CredentialEnv: "INTENT_CREDENTIAL",
	}
	wrapper, err := agentid.NewMCPWrapper(agentid.MCPWrapperConfig{
		Tools: []agentid.ToolMapping{mapping}, Chain: []agentid.Delegation{delegation},
		Profile: w.profile, RootKeyPEM: pub, Signer: signer,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	request, _ := agentid.DecodeJSON(agentid.MCPRequestJSON(1, "intent.tool", map[string]any{
		"amount": "100.00", "currency": "USD", "region": "eu",
	}))
	return wrapper.HandleRPC(context.Background(), agentid.AsMap(request))
}

func (w *World) CompileIntent(text string) map[string]any {
	w.t.Helper()
	w.intent = agentid.CompileIntent(text)
	return w.intent.ToMap()
}

func (w *World) ActivateIntent(candidate map[string]any) map[string]any {
	w.t.Helper()
	return w.callWithDelegation(w.intent.Draft, w.rootPub, w.signer)
}

func (w *World) CompilerUnmatched(candidate map[string]any) []any {
	w.t.Helper()
	if items, ok := candidate["unmatched"].([]any); ok {
		return items
	}
	return nil
}

func CompilerDigest(candidate map[string]any) string {
	if digest, ok := candidate["digest"].(string); ok {
		return digest
	}
	return ""
}

func (w *World) ActivateIntentWithReview(candidate map[string]any) map[string]any {
	w.t.Helper()
	reviewer, reviewerPub, err := agentid.GenerateKeyPair()
	if err != nil {
		w.t.Fatal(err)
	}
	reviewSigner, err := agentid.NewDevSigner(reviewer, reviewerPub, "reviewer_key")
	if err != nil {
		w.t.Fatal(err)
	}
	approval, err := agentid.SignApproval(map[string]any{
		"id": "apr_intent", "approver": "human@rp", "nonce": "intent-1",
		"approves_compilation_digest": w.intent.Digest,
	}, reviewSigner)
	if err != nil {
		w.t.Fatal(err)
	}
	active, err := agentid.ActivateIntent(w.intent, approval, w.signer)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.callWithDelegation(active, w.rootPub, w.signer)
}
