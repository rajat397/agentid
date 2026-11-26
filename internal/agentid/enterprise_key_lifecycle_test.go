//go:build enterprise
// SPDX-License-Identifier: LicenseRef-agentid-commercial

package agentid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeyGenerateHardensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	dir := filepath.Join(t.TempDir(), "keys")
	if _, err := GenerateLocalKey(dir, "kid-one"); err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(filepath.Join(dir, "kid-one", "private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %o", privateInfo.Mode().Perm())
	}
	publicInfo, err := os.Stat(filepath.Join(dir, "kid-one", "public.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if publicInfo.Mode().Perm() != 0644 {
		t.Fatalf("public key mode = %o", publicInfo.Mode().Perm())
	}
}

func TestKeyRotatePublishesOverlap(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if _, err := GenerateLocalKey(dir, "kid-one"); err != nil {
		t.Fatal(err)
	}
	if _, err := RotateLocalKey(dir, "kid-two"); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "keys.json")
	if err := PublishLocalKeys(dir, out); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Version string `json:"version"`
		Keys    []struct {
			Kid       string `json:"kid"`
			State     string `json:"state"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != "v1" || len(decoded.Keys) != 2 {
		t.Fatalf("unexpected key set: %s", data)
	}
	states := map[string]string{}
	for _, key := range decoded.Keys {
		states[key.Kid] = key.State
		if !strings.Contains(key.PublicKey, "PUBLIC KEY") {
			t.Fatalf("public key missing PEM: %s", key.PublicKey)
		}
	}
	if states["kid-one"] != "previous" || states["kid-two"] != "active" {
		t.Fatalf("unexpected states: %+v", states)
	}
}

