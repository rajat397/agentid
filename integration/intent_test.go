package integration

import (
	"strings"
	"testing"
)

// Scenario: an operator writes intent in natural language. The compiler may
// propose a constrained draft, but it never creates live authority; a human
// review signature activates exactly that digest.
func TestScenarioIntentCompilerRequiresHumanReview(t *testing.T) {
	w := NewWorld(t)

	intent := "Agent marketing-agent may purchase ad credit on meta-ads up to 2000 USD " +
		"until 2030-01-01; require approval above 500; only EU region."
	candidate := w.CompileIntent(intent)
	if candidate == nil {
		t.Fatal("compiler stub still active")
	}
	if len(w.CompilerUnmatched(candidate)) != 0 {
		t.Fatalf("known intent left unmatched: %v", w.CompilerUnmatched(candidate))
	}
	if !strings.Contains(CompilerDigest(candidate), "") {
		t.Fatal("candidate has no compilation digest")
	}

	active := w.ActivateIntent(candidate)
	if active == nil || AsMapValue(active["error"]) == nil {
		t.Fatalf("unsigned draft was activated: %+v", active)
	}

	approved := w.ActivateIntentWithReview(candidate)
	if approved == nil || AsMapValue(approved["error"]) != nil {
		t.Fatalf("human-approved compilation rejected: %+v", approved)
	}

	ambiguous := w.CompileIntent("do whatever is needed to help the company")
	if len(w.CompilerUnmatched(ambiguous)) == 0 {
		t.Fatal("ambiguous intent produced no unmatched clauses")
	}
}
