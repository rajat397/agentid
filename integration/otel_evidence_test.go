package integration

import (
	"strings"
	"testing"
)

// Scenario: OTel is the channel where operators see reality. Every moment of
// one consequential action must be a span mutually bound to its receipt, must
// survive W3C propagation, and must be reconcilable against the ledger.
func TestScenarioOTelEvidenceLayer(t *testing.T) {
	w := NewWorld(t)

	w.expectAllowed(w.callTool("100.00"))
	receipt := w.ledger.Receipts[0]

	w.EvidenceSpans()
	if len(w.evidenceSpans) != 5 {
		t.Fatalf("expected five evidence spans, got %d", len(w.evidenceSpans))
	}
	receiptIDs := map[string]bool{}
	for _, span := range w.evidenceSpans {
		id, _ := span["receipt_id"].(string)
		if id != receipt.ID {
			t.Fatalf("span is not bound to the receipt: %v", span["receipt_id"])
		}
		receiptIDs[id] = true
	}
	if len(receiptIDs) != 1 {
		t.Fatal("spans do not share one receipt binding")
	}
	if w.spanTraceID == "" {
		t.Fatal("no W3C trace id was propagated")
	}

	if problems := w.SpanProblems(); len(problems) > 0 {
		t.Fatalf("clean reconciliation failed: %v", problems)
	}

	serialized := spanSetJSON(w.evidenceSpans)
	if strings.Contains(serialized, "cust_4471") {
		t.Fatal("raw subject reference leaked into spans by default")
	}

	tampered := make([]map[string]any, len(w.evidenceSpans))
	for i, span := range w.evidenceSpans {
		copy := map[string]any{}
		for key, value := range span {
			copy[key] = value
		}
		tampered[i] = copy
	}
	tampered[1]["decision"] = "denied"
	if problems := w.SpanProblemsFor(tampered); len(problems) == 0 {
		t.Fatal("tampered span decision was not detected")
	}
}
