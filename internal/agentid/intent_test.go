package agentid

import (
	"strings"
	"testing"
)

func TestIntentCompilerBoundedPatterns(t *testing.T) {
	compilation := CompileIntent("Agent marketing-agent may purchase ad credit on meta-ads " +
		"up to 2000 USD until 2030-01-01; require approval above 500; only EU region.")
	if len(compilation.Unmatched) != 0 {
		t.Fatalf("known intent unmatched: %v", compilation.Unmatched)
	}
	if stringValue(compilation.Plan["actor_id"]) != "marketing-agent" ||
		stringValue(compilation.Plan["system"]) != "meta-ads" {
		t.Fatalf("wrong plan: %+v", compilation.Plan)
	}
	if !compilation.Draft.Draft {
		t.Fatal("compiler produced live authority")
	}
	ambiguous := CompileIntent("do whatever is needed")
	if len(ambiguous.Unmatched) == 0 {
		t.Fatal("ambiguous intent produced no unmatched clauses")
	}
}

func TestActivationRequiresExactDigest(t *testing.T) {
	compilation := CompileIntent("Agent a may purchase ad credit on s up to 100 USD until 2030-01-01")
	if len(compilation.Unmatched) != 0 {
		t.Fatalf("intent unmatched: %v", compilation.Unmatched)
	}
	signer, _ := newSigner(t, "activation_signer")
	reviewer, _ := newSigner(t, "activation_reviewer")
	approval, err := SignApproval(map[string]any{
		"id": "apr", "approver": "human", "nonce": "n",
		"approves_compilation_digest": "wrong",
	}, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ActivateIntent(compilation, approval, signer); err == nil {
		t.Fatal("wrong compilation digest was approved")
	}
	approval, err = SignApproval(map[string]any{
		"id": "apr2", "approver": "human", "nonce": "n2",
		"approves_compilation_digest": compilation.Digest,
	}, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	active, err := ActivateIntent(compilation, approval, signer)
	if err != nil || active.Draft {
		t.Fatalf("activation failed: %v %+v", err, active)
	}
}

func TestDraftDelegationIsDenied(t *testing.T) {
	signer, pub := newSigner(t, "draft_key")
	compilation := CompileIntent("Agent a may purchase ad credit on s up to 100 USD until 2030-01-01")
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "s",
		"amount": "10.00", "currency": "USD",
	}
	_, result, err := Act(&Ledger{}, []Delegation{compilation.Draft}, action,
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "draft") {
		t.Fatalf("draft delegation was accepted: %+v", result)
	}
}
