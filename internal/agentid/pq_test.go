package agentid

import (
	"strings"
	"testing"
)

func TestDefaultDualSignsReceiptsAndVerifies(t *testing.T) {
	signer, pub := newSigner(t, "pq_es_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	receipt, result, err := Act(ledger, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("outcome: %s (%s)", result.Outcome, result.Reason)
	}
	if receipt.Signature.Alg != "ES256" || len(receipt.Signatures) != 1 {
		t.Fatalf("expected ES256 primary + 1 extra signature: %+v %+v",
			receipt.Signature, receipt.Signatures)
	}
	if receipt.Signatures[0].Alg != AlgMLDSA65 {
		t.Fatalf("unexpected PQ algorithm: %s", receipt.Signatures[0].Alg)
	}
	if problems := ledger.VerifyChain(ledger.SignerKeys); len(problems) > 0 {
		t.Fatalf("dual-signed chain failed verification: %v", problems)
	}
	receipt.Signatures[0].Value = "tampered"
	problems := ledger.VerifyChain(ledger.SignerKeys)
	if len(problems) == 0 || !strings.Contains(problems[0], "additional signature") {
		t.Fatalf("tampered PQ signature accepted: %v", problems)
	}
}

func TestPQOptOutViaProfile(t *testing.T) {
	signer, pub := newSigner(t, "optout_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	document := ExampleProfile().document()
	document["pq_sign"] = false
	profile, err := ProfileFromMap(document)
	if err != nil {
		t.Fatal(err)
	}
	if profile.AllowsPQ() {
		t.Fatal("profile did not record pq_sign=false")
	}
	ledger := &Ledger{}
	receipt, _, err := Act(ledger, []Delegation{delegation}, testAction(),
		profile, pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Signatures) != 0 {
		t.Fatalf("PQ signature present despite opt-out: %+v", receipt.Signatures)
	}
}

func TestDelegationIsDualSignedAndVerifiable(t *testing.T) {
	signer, pub := newSigner(t, "dlg_pq_key")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if len(delegation.Signatures) != 1 || delegation.Signatures[0].Alg != AlgMLDSA65 {
		t.Fatalf("delegation not dual-signed: %+v", delegation.Signatures)
	}
	if !VerifySignature(delegation.Signature.Alg,
		delegation.SignerKeys[delegation.Signature.Kid],
		delegation.UnsignedBody(), delegation.Signature.Value) {
		t.Fatal("primary delegation signature failed")
	}
	pq := delegation.Signatures[0]
	if !VerifySignature(pq.Alg, delegation.SignerKeys[pq.Kid],
		delegation.UnsignedBody(), pq.Value) {
		t.Fatal("PQ delegation signature failed")
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("dual-signed delegation rejected: %s", result.Reason)
	}
}

func TestPQFlagIsPartOfProfileDigest(t *testing.T) {
	withPQ := ExampleProfile()
	without := ExampleProfile()
	without.PQSign = false
	first, _ := withPQ.Digest()
	second, _ := without.Digest()
	if first == second {
		t.Fatal("pq_sign is not bound into the profile digest")
	}
}
