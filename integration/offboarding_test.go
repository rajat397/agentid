package integration

import (
	"sync/atomic"
	"testing"
)

// Scenario: an employee is deprovisioned in the enterprise directory. The
// agent's authority must be revoked in the published status list and an
// already-running PEP must stop calling the downstream tool. The evidence
// bundle must still verify after the revocation.
func TestScenarioDeprovisionStopsToolCalls(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))
	if atomic.LoadInt64(w.adsCalls) != 1 {
		t.Fatalf("allowed call did not reach downstream: %d", atomic.LoadInt64(w.adsCalls))
	}

	w.scimActive.Store(false)
	w.Deprovision()
	w.RefreshWrapper()
	w.AssertStatus(0x01)

	w.expectDenied(w.callTool("100.00"))
	if atomic.LoadInt64(w.adsCalls) != 1 {
		t.Fatalf("denied call reached downstream: %d", atomic.LoadInt64(w.adsCalls))
	}
}
