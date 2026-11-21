package integration

import "testing"

// Scenario: embedded validation keeps the hot path local, but one control
// plane owns policy, revocation and anchoring. A published policy change must
// reach the PEP on refresh; a stale cache must fail closed with a receipt.
func TestScenarioControlPlanePolicyRefreshAndStaleness(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))

	w.PublishPolicyChange()
	w.RefreshPEP()
	w.expectDenied(w.callTool("100.00"))

	w.controlPlane = false
	w.RefreshPEP()
	w.expectDenied(w.callTool("100.00"))

	if problems := w.ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("control-plane decisions broke the chain: %v", problems)
	}
}
