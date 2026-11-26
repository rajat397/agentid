//go:build enterprise
// SPDX-License-Identifier: LicenseRef-agentid-commercial

package agentid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIOperatorConfigCommands(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agentid.json")
	body := `{"version":"v1","mode":"shadow","tools":[{"name":"purchase","action":"ad.credit.purchase","system":"meta-ads","resource_type":"ad_credit_account","allowed_args":["amount"]}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	out, _, code := runCLI(t, "config", "check", "--config", path)
	if code != 0 || !strings.Contains(out, "VALID") {
		t.Fatalf("config check failed: %d %s", code, out)
	}

	out, _, code = runCLI(t, "health", "--config", path)
	if code != 0 || !strings.Contains(out, `"mode":"shadow"`) {
		t.Fatalf("health failed: %d %s", code, out)
	}
}

func TestCLILocalKeyLifecycle(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	out, _, code := runCLI(t, "key", "generate", "--dir", dir, "--kid", "cli-one")
	if code != 0 || !strings.Contains(out, "cli-one") {
		t.Fatalf("key generate failed: %d %s", code, out)
	}
	out, _, code = runCLI(t, "key", "rotate", "--dir", dir, "--kid", "cli-two")
	if code != 0 || !strings.Contains(out, "cli-two") {
		t.Fatalf("key rotate failed: %d %s", code, out)
	}
	published := filepath.Join(t.TempDir(), "keys.json")
	out, _, code = runCLI(t, "key", "publish", "--dir", dir, "--out", published)
	if code != 0 || !strings.Contains(out, "wrote") {
		t.Fatalf("key publish failed: %d %s", code, out)
	}
}
