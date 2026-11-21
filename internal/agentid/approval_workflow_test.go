package agentid

import "testing"

func TestApprovalWorkflowLifecycle(t *testing.T) {
	workflow := NewApprovalWorkflow()
	request, err := workflow.Request("a.purchase", "s", "dlg_1", "digest", "cosign_above", "reason")
	if err != nil {
		t.Fatal(err)
	}
	if request.Status != "pending" || len(workflow.List("pending")) != 1 {
		t.Fatal("request is not pending")
	}
	reviewer, _ := newSigner(t, "workflow_reviewer")
	approved, err := workflow.Review(request.ID, true, reviewer, "ok")
	if err != nil || approved.Status != "approved" {
		t.Fatalf("approval failed: %v %+v", err, approved)
	}
	if err := VerifyApprovalSignature(approved.Approval); err != nil {
		t.Fatalf("workflow approval artifact invalid: %v", err)
	}
	if len(workflow.List("pending")) != 0 {
		t.Fatal("approved request still pending")
	}
	if _, err := workflow.Review(request.ID, false, reviewer, "late"); err == nil {
		t.Fatal("review of non-pending request accepted")
	}
}

func TestApprovalWorkflowRejectionAndValidation(t *testing.T) {
	workflow := NewApprovalWorkflow()
	if _, err := workflow.Request("a", "s", "d", "", "cosign_above", "r"); err == nil {
		t.Fatal("request without envelope digest accepted")
	}
	request, _ := workflow.Request("a", "s", "d", "digest", "cosign_untrusted", "r")
	rejected, err := workflow.Review(request.ID, false, nil, "no")
	if err != nil || rejected.Status != "rejected" {
		t.Fatalf("rejection failed: %v %+v", err, rejected)
	}
}
