package integration

import (
	"testing"
)

// Scenario: the PEP raises a reviewable request instead of an unexplained
// denial. Approval and rejection are explicit workflow states; only an
// approved, signed artifact can discharge the obligation on retry.
func TestScenarioApprovalWorkflow(t *testing.T) {
	w := NewWorld(t)

	denied := w.RequestOverThreshold()
	if denied == nil {
		t.Fatal("workflow stub still active")
	}
	requestID := w.ApprovalRequestID(denied)
	if requestID == "" {
		t.Fatalf("denial carries no approval request id: %+v", denied)
	}

	approved := w.ReviewPending(true)
	if w.RequestStatus(approved) != "approved" {
		t.Fatalf("approval not recorded: %+v", approved)
	}
	if result := w.RetryWithApproval(denied); result == nil || AsMapValue(result["error"]) != nil {
		t.Fatalf("approved retry was blocked: %+v", result)
	}

	w.RequestOverThreshold()
	rejected := w.ReviewPending(false)
	if w.RequestStatus(rejected) != "rejected" {
		t.Fatalf("rejection not recorded: %+v", rejected)
	}
}
