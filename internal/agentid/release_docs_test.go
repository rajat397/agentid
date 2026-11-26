package agentid

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPagesWorkflowWaitsForArtifact(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/pages.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"actions: read",
		"upload-pages-artifact@v3",
		"Wait for Pages artifact metadata",
		"/actions/runs/${GITHUB_RUN_ID}/artifacts",
		"deploy-pages@v4",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("pages workflow missing %q", want)
		}
	}
}

func TestReleaseDocsContract(t *testing.T) {
	files := map[string][]string{
		"../../UPGRADING.md": {
			"Compatibility matrix", "Rollback", "verify", "digest",
		},
		"../../docs/reference/releases.md": {
			"Semantic versioning", "release checklist", "security release", "redeploy",
		},
		"../../scripts/release-check.sh": {
			"$go_bin\" test ./...", "$go_bin\" vet ./...", "SHA256SUMS", "version",
		},
	}
	for path, wants := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(data), want) {
				t.Fatalf("%s missing %q", path, want)
			}
		}
	}
	if err := exec.Command("bash", "-n", "../../scripts/release-check.sh").Run(); err != nil {
		t.Fatalf("release-check syntax: %v", err)
	}
}
