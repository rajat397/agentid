package integration

import (
	"strings"
	"testing"
)

// Scenario: GDPR Art. 17 execution against two downstream systems. A connector
// failure must halt the run, leave no receipt for the failed action, and a
// retry after recovery must complete with deletion receipts and a clean verify.
func TestScenarioErasureExecutionAndFailClosed(t *testing.T) {
	w := NewWorld(t)
	w.zendesk = &mockDownstream{system: "zendesk", records: map[string]bool{"cust_4471": true}}
	w.crm = &mockDownstream{system: "crm", records: map[string]bool{"cust_4471": true}}

	w.crm.fail = true
	w.ErasureExec()
	if w.erasureError == nil || !strings.Contains(w.erasureError.Error(), "ERASURE_INCOMPLETE") {
		t.Fatalf("connector failure did not halt: %v", w.erasureError)
	}
	if len(w.erasureReceipts) != 1 {
		t.Fatalf("completed deletion should still be receipted: %d", len(w.erasureReceipts))
	}
	if agentid := "zendesk"; stringValueOf(AsMapValue(w.erasureReceipts[0].Resource["attributes"])["system"]) != agentid {
		t.Fatalf("unexpected partial receipt: %+v", w.erasureReceipts[0].Resource)
	}

	w.crm.fail = false
	w.ErasureExec()
	if w.erasureError != nil {
		t.Fatalf("retry failed: %v", w.erasureError)
	}
	if len(w.erasureReceipts) != 3 {
		t.Fatalf("expected three deletion receipts across both runs, got %d", len(w.erasureReceipts))
	}
	if w.zendesk.records["cust_4471"] || w.crm.records["cust_4471"] {
		t.Fatal("downstream systems still hold the subject")
	}
	if problems := w.ledger.VerifyChain(nil); len(problems) > 0 {
		t.Fatalf("deletion receipts broke the chain: %v", problems)
	}

	w.ErasureVerify()
	if len(w.verifyProblems) > 0 {
		t.Fatalf("erasure verification failed: %v", w.verifyProblems)
	}
}

func AsMapValue(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

func stringValueOf(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
