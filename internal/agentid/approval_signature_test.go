package agentid

import "testing"

func approvalTestSetup(t *testing.T) (Delegation, []byte, map[string]any) {
	t.Helper()
	signer, pub := newSigner(t, "approval_key")
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"max_amount":                    map[string]any{"value": "2000.00", "currency": "USD"},
		"requires_human_approval_above": map[string]any{"value": "500.00", "currency": "USD"},
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", constraints,
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	approval := map[string]any{
		"id": "apr_1", "delegation_id": delegation.ID,
		"action": "ad.credit.purchase", "amount": "1500.00",
		"approver": "human@rp", "nonce": "n1",
	}
	return delegation, pub, approval
}

func TestUnsignedApprovalRejectedByRealProfile(t *testing.T) {
	delegation, pub, approval := approvalTestSetup(t)
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": "1500.00", "currency": "USD",
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{Approval: approval})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" {
		t.Fatalf("unsigned approval was accepted: %+v", result)
	}
}

func TestSignedApprovalDischargesObligation(t *testing.T) {
	delegation, pub, approval := approvalTestSetup(t)
	approver, _ := newSigner(t, "human_signer")
	signed, err := SignApproval(approval, approver)
	if err != nil {
		t.Fatal(err)
	}
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": "1500.00", "currency": "USD",
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{Approval: signed})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("signed approval rejected: %+v", result)
	}
}

func TestTamperedSignedApprovalRejected(t *testing.T) {
	delegation, pub, approval := approvalTestSetup(t)
	approver, _ := newSigner(t, "human_signer")
	signed, err := SignApproval(approval, approver)
	if err != nil {
		t.Fatal(err)
	}
	signed["amount"] = "2000.00"
	action := map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": "1500.00", "currency": "USD",
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{Approval: signed})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" {
		t.Fatalf("tampered approval accepted: %+v", result)
	}
}
