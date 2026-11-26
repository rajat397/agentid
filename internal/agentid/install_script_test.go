package agentid

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestContainerArtifactContract(t *testing.T) {
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"golang:1.27", "distroless", "ENTRYPOINT", "USER 65532"} {
		if !strings.Contains(string(dockerfile), want) {
			t.Fatalf("Dockerfile missing %q", want)
		}
	}
	workflow, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"packages: write",
		"ghcr.io/rajat397/agentid",
		"docker/build-push-action",
		"cosign sign",
		"steps.build.outputs.digest",
	} {
		if !strings.Contains(string(workflow), want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}
}

func TestInstallScriptContract(t *testing.T) {
	path := "../../scripts/install.sh"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, want := range []string{
		"cosign verify-blob",
		"sha256sum --check",
		"AGENTID_VERSION",
		"INSTALL_DIR",
		"AGENTID_RELEASE_BASE",
		"certificate-oidc-issuer",
		"certificate-identity-regexp",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install script missing %q", want)
		}
	}
	for _, forbidden := range []string{"--insecure-ignore-tlog", "curl -fsSL | sh"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("install script contains forbidden pattern %q", forbidden)
		}
	}
	if err := exec.Command("bash", "-n", path).Run(); err != nil {
		t.Fatalf("install script syntax: %v", err)
	}
}
