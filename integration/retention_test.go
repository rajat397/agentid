package integration

import (
	"os"
	"testing"
)

// Scenario: after the retention window, receipts are exported to customer
// storage and an ARCHIVE receipt is appended. Erasure tombstones a subject
// without rewriting the evidence chain or dropping anchors.
func TestScenarioRetentionArchiveAndErasureTombstone(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))
	w.expectAllowed(w.callTool("100.00"))

	w.ExportRetention()
	if w.archivePath == "" || w.archiveReceipt == nil {
		t.Fatal("retention export produced no archive or ARCHIVE receipt")
	}
	if _, err := os.Stat(w.archivePath); err != nil {
		t.Fatalf("archive not written to customer storage: %v", err)
	}
	if problems := w.ArchiveProblem(); len(problems) > 0 {
		t.Fatalf("archive verification failed: %v", problems)
	}
	if problems := w.ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("ARCHIVE receipt broke the hash chain: %v", problems)
	}

	w.TombstoneSubject()
	if len(w.tombstones) == 0 {
		t.Fatal("erasure did not record a tombstone")
	}
	if problems := w.ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("tombstone broke the hash chain: %v", problems)
	}
}
