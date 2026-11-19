package agentid

import (
	"strings"
	"testing"
)

func audienceDelegation(t *testing.T, aud string) (Delegation, []byte) {
	t.Helper()
	signer, pub := newSigner(t, "audience_key")
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": "ad.credit.purchase", "system": "meta-ads"}},
		"budget": map[string]any{
			"key": "ads_q4", "value": "100.00", "currency": "USD",
		},
	}
	if aud != "" {
		constraints["aud"] = aud
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", constraints,
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	return delegation, pub
}

func audienceAction(aud, amount string) map[string]any {
	return map[string]any{
		"action": "ad.credit.purchase", "system": "meta-ads",
		"amount": amount, "currency": "USD", "budget_key": "ads_q4",
		"aud": aud, "resource_type": "ad_credit_account", "resource_id": "acct",
	}
}

func TestBudgetsArePartitionedByAudience(t *testing.T) {
	delegation, pub := audienceDelegation(t, "")
	ledger := &Ledger{}
	for _, item := range []struct {
		aud, amount string
	}{
		{"rp1", "60.00"}, {"rp2", "60.00"},
	} {
		receipt, result, err := Act(ledger, []Delegation{delegation},
			audienceAction(item.aud, item.amount), ExampleProfile(), pub, ActOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Outcome != "valid" {
			t.Fatalf("first %s spend rejected: %s", item.aud, result.Reason)
		}
		attributes := AsMap(receipt.Resource["attributes"])
		if stringField(attributes, "aud") != item.aud {
			t.Fatalf("receipt does not record audience: %+v", attributes)
		}
	}
	_, denied, err := Act(ledger, []Delegation{delegation},
		audienceAction("rp1", "50.00"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Outcome != "invalid" || !strings.Contains(denied.Reason, "budget exhausted") {
		t.Fatalf("rp2 spend leaked into rp1 budget: %s", denied.Reason)
	}
	_, allowed, err := Act(ledger, []Delegation{delegation},
		audienceAction("rp2", "40.00"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Outcome != "valid" {
		t.Fatalf("rp2 bucket was consumed by rp1: %s", allowed.Reason)
	}
}

func TestAudPinningAndAttenuation(t *testing.T) {
	delegation, pub := audienceDelegation(t, "rp1")
	_, denied, err := Act(&Ledger{}, []Delegation{delegation},
		audienceAction("rp2", "10.00"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Outcome != "invalid" || !strings.Contains(denied.Reason, "aud pinning") {
		t.Fatalf("wrong audience accepted: %s", denied.Reason)
	}
	_, allowed, err := Act(&Ledger{}, []Delegation{delegation},
		audienceAction("rp1", "10.00"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Outcome != "valid" {
		t.Fatalf("pinned audience rejected: %s", allowed.Reason)
	}

	signer, _ := newSigner(t, "aud_attenuation")
	subject := map[string]any{"type": "human", "id": "usr"}
	parentConstraints := map[string]any{
		"permissions": []any{map[string]any{"action": "a", "system": "s"}},
		"aud":         "rp1",
	}
	parent, err := CreateDelegation(nil, subject, "agent", parentConstraints,
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	childConstraints := map[string]any{
		"permissions": []any{map[string]any{"action": "a", "system": "s"}},
		"aud":         "rp2",
	}
	if _, err := CreateDelegation(nil, subject, "child", childConstraints,
		"2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true, Parent: &parent}); err == nil {
		t.Fatal("child changed the pinned audience")
	}
}
