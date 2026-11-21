package agentid

import (
	"os"
	"testing"
	"time"
)

func retentionLedger(t *testing.T) *Ledger {
	t.Helper()
	signer, pub := newSigner(t, "retention_key")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	action := testAction()
	action["personal_data_refs"] = []any{"cust_1"}
	if _, _, err := Act(ledger, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{}); err != nil {
		t.Fatal(err)
	}
	return ledger
}

func TestRetentionArchiveAndTombstone(t *testing.T) {
	ledger := retentionLedger(t)
	dir := t.TempDir()
	path, receipt, err := ExportArchive(ledger, RetentionPolicy{
		WindowMonths: DefaultRetentionMonths, ArchiveDir: dir,
	}, time.Now().AddDate(0, 14, 0))
	if err != nil {
		t.Fatal(err)
	}
	if problems := VerifyArchive(path, receipt); len(problems) > 0 {
		t.Fatalf("archive failed verification: %v", problems)
	}
	if problems := ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("ARCHIVE receipt broke chain: %v", problems)
	}
	tombstone, err := Tombstone(ledger, "cust_1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !IsTombstoned(ledger, "cust_1") || tombstone.ActionType != "tombstone" {
		t.Fatal("tombstone not recorded")
	}
	if problems := ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("tombstone broke chain: %v", problems)
	}
	original := ledger.Receipts[0]
	if len(original.PersonalDataRefs()) != 1 {
		t.Fatal("original receipt was mutated in place")
	}
}

func TestRetentionRejectsEmptyAndTamperedArchive(t *testing.T) {
	ledger := retentionLedger(t)
	if _, _, err := ExportArchive(ledger, RetentionPolicy{ArchiveDir: t.TempDir()},
		time.Now().AddDate(0, -1, 0)); err == nil {
		t.Fatal("exported receipts inside the retention window")
	}
	_, receipt, err := ExportArchive(ledger, RetentionPolicy{ArchiveDir: t.TempDir()},
		time.Now().AddDate(0, 14, 0))
	if err != nil {
		t.Fatal(err)
	}
	path := stringValue(AsMap(AsMap(receipt.Resource)["attributes"])["archive_uri"])
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("{}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if problems := VerifyArchive(path, receipt); len(problems) == 0 {
		t.Fatal("tampered archive verified")
	}
	if _, err := Tombstone(ledger, "unknown", time.Now()); err == nil {
		t.Fatal("tombstone for unknown subject succeeded")
	}
}
