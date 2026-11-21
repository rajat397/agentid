package agentid

import (
	"testing"
	"time"
)

func testControlPlane(t *testing.T) (*ControlPlane, *PolicyCache, Signer) {
	t.Helper()
	signer, _ := newSigner(t, "cp_key")
	registry, err := OpenFileRegistry(t.TempDir() + "/registry.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("usr_1", "dlg_1", 0); err != nil {
		t.Fatal(err)
	}
	publisher := StatusPublisher{Registry: registry, Signer: signer,
		URI: "https://example.invalid/status", TTL: 300}
	anchors, err := NewAnchorManager(AnchorConfig{
		Flavor: "bucket", BucketDir: t.TempDir(), BucketSigner: signer,
		Cadence: AnchorCadence{MaxReceipts: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	cp, err := NewControlPlane(signer, registry, publisher, anchors)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cp.PublishPolicy(ExampleProfile()); err != nil {
		t.Fatal(err)
	}
	bundle, err := cp.PolicyBundle()
	if err != nil {
		t.Fatal(err)
	}
	cache := NewPolicyCache(signer.PublicKeys(), time.Minute)
	if err := cache.Refresh(bundle); err != nil {
		t.Fatal(err)
	}
	return cp, cache, signer
}

func TestPolicyBundleSignatureAndDigestAreEnforced(t *testing.T) {
	_, cache, _ := testControlPlane(t)
	cp, _, _ := testControlPlane(t)
	bundle, err := cp.PolicyBundle()
	if err != nil {
		t.Fatal(err)
	}
	bundle.Signature.Value = "tampered"
	if err := cache.Refresh(bundle); err == nil {
		t.Fatal("tampered policy bundle accepted")
	}

	cp2, _, signer := testControlPlane(t)
	valid, err := cp2.PolicyBundle()
	if err != nil {
		t.Fatal(err)
	}
	valid.Digest = "0"
	valid.Signature, err = signer.Sign(valid.body())
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(valid); err == nil {
		t.Fatal("bundle with mismatched digest accepted")
	}
}

func TestStaleCacheFailsClosed(t *testing.T) {
	_, cache, _ := testControlPlane(t)
	if _, err := cache.Profile(); err != nil {
		t.Fatalf("fresh cache rejected: %v", err)
	}
	cache.Expire()
	if _, err := cache.Profile(); err == nil {
		t.Fatal("stale cache did not fail closed")
	}
}

func TestControlPlaneOrchestratesStatusAndAnchors(t *testing.T) {
	cp, _, _ := testControlPlane(t)
	token, err := cp.PublishStatus()
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := VerifyStatusTokenAtIssuedTime(token,
		map[string]string{cp.signer.Kid(): publicKeyOf(t, cp.signer)},
		ExampleProfile().MaxStatusAge); err != nil || payload["status_count"] == nil {
		t.Fatalf("published status token invalid: %v %v", payload, err)
	}
	snapshot := cp.Snapshot()
	if intValue(snapshot["published_policies"]) != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func publicKeyOf(t *testing.T, signer Signer) string {
	t.Helper()
	keys := signer.PublicKeys()
	for _, material := range keys {
		return material
	}
	t.Fatal("signer has no public key")
	return ""
}
