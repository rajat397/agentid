package agentid

import (
	"path/filepath"
	"testing"
)

func TestBucketStampRoundTripAndOfflineVerify(t *testing.T) {
	signer, _ := newSigner(t, "bucket_key")
	head := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	stamp, err := NewBucketStamp(head, 7, signer)
	if err != nil {
		t.Fatal(err)
	}
	path, err := WriteBucketStamp(t.TempDir(), stamp)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBucketStamp(path)
	if err != nil {
		t.Fatal(err)
	}
	if problems := VerifyBucketStamp(loaded, signer.PublicKeys(), head); len(problems) > 0 {
		t.Fatalf("stamp did not verify: %v", problems)
	}
	loaded.HeadHash = "0"
	if problems := VerifyBucketStamp(loaded, signer.PublicKeys(), head); len(problems) == 0 {
		t.Fatal("tampered stamp verified")
	}
}

func TestBucketAnchorManagerNeedsNoTSA(t *testing.T) {
	signer, _ := newSigner(t, "bucket_manager_key")
	manager, err := NewAnchorManager(AnchorConfig{
		Flavor: "bucket", BucketDir: t.TempDir(), BucketSigner: signer,
		Cadence: AnchorCadence{MaxReceipts: 1}, TSAURL: "http://127.0.0.1:1/unusable",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Build a one-receipt ledger without any HTTP dependency.
	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rootSigner, err := NewDevSigner(privatePEM, publicPEM, "root")
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: rootSigner, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	if _, _, err := Act(ledger, []Delegation{delegation}, testAction(),
		ExampleProfile(), publicPEM, ActOptions{}); err != nil {
		t.Fatal(err)
	}
	anchors, err := manager.Observe(ledger, "")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("bucket anchoring failed: %d %v", len(anchors), err)
	}
	if stringField(anchors[0], "flavor") != "bucket" {
		t.Fatalf("unexpected anchor flavor: %+v", anchors[0])
	}
	if gaps := DetectAnchorGaps(anchors, ledger); len(gaps) > 0 {
		t.Fatalf("bucket anchor has gaps: %v", gaps)
	}
}

func TestTransparencyLogFlavorFailsClosed(t *testing.T) {
	if _, err := NewAnchorManager(AnchorConfig{Flavor: "transparency-log"}); err == nil {
		t.Fatal("unimplemented transparency-log flavor was accepted")
	}
}

func TestBucketStampStoredPath(t *testing.T) {
	signer, _ := newSigner(t, "bucket_path_key")
	dir := t.TempDir()
	stamp, err := NewBucketStamp(
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", 3, signer)
	if err != nil {
		t.Fatal(err)
	}
	path, err := WriteBucketStamp(dir, stamp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBucketStamp(filepath.Join(dir, "head-00000003.json")); err != nil {
		t.Fatalf("unexpected stamp path %s: %v", path, err)
	}
}
