package integration

import "testing"

// Scenario: a fleet runs long enough to cross its anchor cadence. The TSA is
// briefly unavailable; writes must continue, the failed anchor must be queued
// and retried, and an auditor must detect a missing anchor in the bundle.
func TestScenarioAnchorCadenceAndGapDetection(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))
	w.ObserveAnchors()
	if len(w.anchors) < 1 {
		t.Fatalf("cadence did not anchor the first head: %d anchors", len(w.anchors))
	}

	w.FailTSA()
	w.expectAllowed(w.callTool("100.00"))
	w.ObserveAnchors()

	w.FixTSA()
	w.expectAllowed(w.callTool("100.00"))
	w.ObserveAnchors()
	if len(w.anchors) < 2 {
		t.Fatalf("queued anchor was not retried: %d anchors", len(w.anchors))
	}

	if gaps := w.DetectGaps(w.anchors[:len(w.anchors)-1]); len(gaps) == 0 {
		t.Fatal("missing anchor was not detected")
	}
	w.VerifyAuditBundle()
}
