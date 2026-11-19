package agentid

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func demoEvidenceBundle(t *testing.T) EvidenceBundle {
	t.Helper()
	demo, err := buildDemoLedger()
	if err != nil {
		t.Fatal(err)
	}
	token, err := BuildStatusToken("https://example.invalid/status",
		[]int{0x00, 0x01}, demo.signer,
		int(dateTimeNow().Unix()), int(dateTimeNow().Unix())+600, 300)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := BuildEvidenceBundle("marketing", demo.ledger,
		[]Delegation{demo.delegation}, ExampleProfile(), nil,
		[]string{token}, demo.signer.PublicKeys())
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestEvidenceBundleVerifiesOffline(t *testing.T) {
	bundle := demoEvidenceBundle(t)
	if problems := VerifyEvidenceBundle(bundle); len(problems) > 0 {
		t.Fatalf("bundle failed verification: %v", problems)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteBundle(path, bundle); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEvidenceBundle(path)
	if err != nil {
		t.Fatal(err)
	}
	if problems := VerifyEvidenceBundle(loaded); len(problems) > 0 {
		t.Fatalf("loaded bundle failed verification: %v", problems)
	}
}

func TestEvidenceBundleDetectsTampering(t *testing.T) {
	base := demoEvidenceBundle(t)

	tamperedReceipt := base
	tamperedReceipt.Receipts = make([]map[string]any, len(base.Receipts))
	for i, receipt := range base.Receipts {
		copy := map[string]any{}
		for key, value := range receipt {
			copy[key] = value
		}
		tamperedReceipt.Receipts[i] = copy
	}
	tamperedReceipt.Receipts[0]["action"] = "social.post.publish"
	if problems := VerifyEvidenceBundle(tamperedReceipt); len(problems) == 0 {
		t.Fatal("tampered receipt accepted")
	}

	badManifest := base
	badManifest.Manifest = map[string]any{"digest": "0"}
	if problems := VerifyEvidenceBundle(badManifest); len(problems) == 0 {
		t.Fatal("manifest mismatch not detected")
	}

	missingKey := base
	missingKey.SignerKeys = map[string]string{}
	if problems := VerifyEvidenceBundle(missingKey); len(problems) == 0 {
		t.Fatal("missing signer key not detected")
	}

	missingDelegation := base
	missingDelegation.Delegations = nil
	if problems := VerifyEvidenceBundle(missingDelegation); len(problems) == 0 {
		t.Fatal("missing delegation not detected")
	}

	badToken := base
	badToken.StatusTokens = []string{"not.a.token"}
	if problems := VerifyEvidenceBundle(badToken); len(problems) == 0 {
		t.Fatal("malformed status token not detected")
	}
}

func TestEvidenceStoreAdapters(t *testing.T) {
	bundle := demoEvidenceBundle(t)
	local := LocalStore{Dir: t.TempDir()}
	uri, err := local.Put(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(uri); err != nil {
		t.Fatalf("local store did not write bundle: %v", err)
	}

	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("unexpected method %s", r.Method)
		}
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	store := PresignedURLStore{URL: server.URL}
	if _, err := store.Put(bundle); err != nil {
		t.Fatal(err)
	}
	if len(received) == 0 {
		t.Fatal("presigned PUT did not carry the bundle")
	}
}
