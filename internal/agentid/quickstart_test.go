package agentid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealQuickstartGatesDownstreamAndVerifiesReceipt(t *testing.T) {
	outDir := t.TempDir()
	const credentialEnv = "AGENTID_QUICKSTART_TEST_TOKEN"
	t.Setenv(credentialEnv, "quickstart-secret")

	result, err := RunQuickstart(outDir, credentialEnv)
	if err != nil {
		t.Fatal(err)
	}
	if result.BlockedCalls != 1 {
		t.Fatalf("blocked calls = %d", result.BlockedCalls)
	}
	if result.DownstreamCallsDenied != 0 {
		t.Fatalf("denied call reached downstream %d times", result.DownstreamCallsDenied)
	}
	if result.DownstreamCallsAllowed != 1 {
		t.Fatalf("allowed call reached downstream %d times", result.DownstreamCallsAllowed)
	}
	if !result.Verified || result.FirstReceipt == "" {
		t.Fatalf("receipt not verified: %+v", result)
	}

	data, err := os.ReadFile(filepath.Join(outDir, "quickstart-bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle["version"] != evidenceVersion {
		t.Fatalf("unexpected bundle version: %v", bundle["version"])
	}
	receipts, ok := bundle["receipts"].([]any)
	if !ok || len(receipts) < 2 {
		t.Fatalf("bundle has no deny/allow receipts: %s", data)
	}
}

func TestCLIQuickstartUsesRealPath(t *testing.T) {
	outDir := t.TempDir()
	out, errOut, code := runCLI(t, "quickstart", "--out", outDir)
	if code != 0 {
		t.Fatalf("quickstart exit %d: %s %s", code, out, errOut)
	}
	for _, want := range []string{"first receipt", "blocked calls", "downstream executed", "offline VERIFIED"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in quickstart output: %s", want, out)
		}
	}
}
