package agentid

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestCLIVersionUsesBuildVersion(t *testing.T) {
	old := BuildVersion
	BuildVersion = "v9.9.9-test"
	defer func() { BuildVersion = old }()

	out, _, code := runCLI(t, "version")
	if code != 0 {
		t.Fatalf("version exit %d: %s", code, out)
	}
	if !strings.Contains(out, "v9.9.9-test") {
		t.Fatalf("version did not use BuildVersion: %s", out)
	}
}

func TestCLICommands(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.jsonl")
	bundlePath := filepath.Join(dir, "bundle.json")

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"version", []string{"version"}, "agentid"},
		{"profile", []string{"profile"}, "digest="},
		{"demo", []string{"demo"}, "Four questions"},
		{"otel-demo", []string{"otel-demo"}, "reconciliation"},
		{"unknown", []string{"nope"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, code := runCLI(t, tc.args...)
			if code != 0 && tc.name != "unknown" {
				t.Fatalf("exit %d: %s", code, out)
			}
			if tc.want != "" && !strings.Contains(out, tc.want) {
				t.Fatalf("missing %q in %s", tc.want, out)
			}
		})
	}

	out, _, code := runCLI(t, "evidence", "export", "--demo", "--out", bundlePath)
	if code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("evidence export failed: %d %s", code, out)
	}
	out, _, code = runCLI(t, "evidence", "verify", "--file", bundlePath)
	if code != 0 || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("evidence verify failed: %d %s", code, out)
	}

	_, _, code = runCLI(t, "anchor-watch", "--ledger", ledgerPath)
	if code == 0 {
		t.Fatal("anchor-watch should fail closed on missing file")
	}
}
