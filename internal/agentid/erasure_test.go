package agentid

import (
	"strings"
	"testing"
)

func TestErasurePlanEnumeratesReceiptsAndSystems(t *testing.T) {
	signer, pub := newSigner(t, "erasure_key")
	subject := map[string]any{"type": "human", "id": "usr_8842"}
	delegations := []Delegation{}
	for _, pair := range []struct{ action, system, fleet string }{
		{"social.post.publish", "meta-ads", "marketing"},
		{"support.reply", "zendesk", "support"},
	} {
		constraints := map[string]any{
			"permissions": []any{map[string]any{"action": pair.action, "system": pair.system}},
		}
		delegation, err := CreateDelegation(nil, subject, pair.fleet+"-agent", constraints,
			"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
		if err != nil {
			t.Fatal(err)
		}
		delegations = append(delegations, delegation)
	}
	ledger := &Ledger{}
	counts := []int{3, 2}
	for i, delegation := range delegations {
		action := "social.post.publish"
		system := "meta-ads"
		if i == 1 {
			action, system = "support.reply", "zendesk"
		}
		for j := 0; j < counts[i]; j++ {
			_, result, err := Act(ledger, []Delegation{delegation}, map[string]any{
				"action": action, "system": system, "resource_type": "ticket",
				"resource_id": "r1", "personal_data_refs": []any{"cust_4471"},
			}, ExampleProfile(), pub, ActOptions{Fleet: delegation.Actor["id"].(string)})
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != "valid" {
				t.Fatalf("seed action invalid: %s", result.Reason)
			}
		}
	}
	registry := map[string][]any{
		"cust_4471": {
			map[string]any{"system": "meta-ads", "records": 88, "method": "customer_connector"},
			map[string]any{"system": "internal_crm", "records": 31, "method": "customer_connector"},
			map[string]any{"system": "zendesk", "records": 2, "method": "customer_connector"},
		},
	}
	plan := BuildErasurePlan(ledger, "cust_4471", registry,
		[]any{map[string]any{"artifact": "campaign_performance_model"}}, "EU")
	if plan.TotalReceipts != 5 || len(plan.Delegations) != 2 {
		t.Fatalf("unexpected plan: receipts=%d delegations=%v", plan.TotalReceipts, plan.Delegations)
	}
	if plan.DaysRemaining != 30 {
		t.Errorf("days remaining: %d", plan.DaysRemaining)
	}
	systems := map[string]bool{}
	for _, raw := range plan.DownstreamSystems {
		systems[stringField(AsMap(raw), "system")] = true
	}
	for _, want := range []string{"meta-ads", "internal_crm", "zendesk"} {
		if !systems[want] {
			t.Errorf("missing downstream system %s", want)
		}
	}
	for _, receipt := range ledger.Receipts {
		serialized, err := CanonicalJSON(receipt.Body())
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"alice@", "555-", "@example.com"} {
			if strings.Contains(string(serialized), leak) {
				t.Errorf("raw personal data leaked: %s", leak)
			}
		}
	}
}

func TestEmptySubjectReturnsEmptyPlan(t *testing.T) {
	plan := BuildErasurePlan(&Ledger{}, "nobody", nil, nil, "EU")
	if plan.TotalReceipts != 0 || len(plan.Delegations) != 0 || plan.DaysRemaining != 30 {
		t.Fatalf("unexpected empty plan: %+v", plan)
	}
}
