package agentid

import (
	"strings"
	"testing"
)

func sensitivityDelegation(t *testing.T, ceiling string) (Delegation, []byte) {
	t.Helper()
	signer, pub := newSigner(t, "sensitivity_key")
	constraints := map[string]any{
		"permissions": []any{map[string]any{
			"action": "support.ticket.purge", "system": "zendesk"}},
		"predicates": []any{
			map[string]any{"type": "max", "path": "/attributes/sensitivity_rank",
				"value": ceiling},
			map[string]any{"type": "sum_max", "path": "/attributes/rows",
				"key": "regulated", "max": "100"},
		},
	}
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent", constraints,
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	return delegation, pub
}

func sensitivityAction(tier, rows string) map[string]any {
	return map[string]any{
		"action": "support.ticket.purge", "system": "zendesk",
		"resource_type": "ticket", "resource_id": "bulk",
		"sensitivity_tier": tier, "rows": rows, "budget_key": "regulated",
	}
}

func TestSensitivityCeilingUsesDerivedRank(t *testing.T) {
	delegation, pub := sensitivityDelegation(t, "2")
	_, result, err := Act(&Ledger{}, []Delegation{delegation},
		sensitivityAction(TierRegulated, "1"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "sensitivity_rank") {
		t.Fatalf("regulated action passed a confidential ceiling: %s", result.Reason)
	}
	receipt, result, err := Act(&Ledger{}, []Delegation{delegation},
		sensitivityAction(TierInternal, "1"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("internal action rejected: %s", result.Reason)
	}
	attributes := AsMap(receipt.Resource["attributes"])
	if stringField(attributes, "sensitivity_tier") != TierInternal ||
		stringField(attributes, "sensitivity_rank") != "1" {
		t.Fatalf("receipt missing sensitivity evidence: %+v", attributes)
	}
}

func TestSensitivityAggregationPerTier(t *testing.T) {
	delegation, pub := sensitivityDelegation(t, "3")
	ledger := &Ledger{}
	for _, rows := range []string{"60", "30"} {
		_, result, err := Act(ledger, []Delegation{delegation},
			sensitivityAction(TierRegulated, rows), ExampleProfile(), pub, ActOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Outcome != "valid" {
			t.Fatalf("%s-row action rejected: %s", rows, result.Reason)
		}
	}
	_, result, err := Act(ledger, []Delegation{delegation},
		sensitivityAction(TierRegulated, "20"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "budget exhausted") {
		t.Fatalf("cumulative exposure cap bypassed: %s", result.Reason)
	}
}

func TestForgedRankAndUnknownTierRejected(t *testing.T) {
	delegation, pub := sensitivityDelegation(t, "3")
	action := sensitivityAction(TierRegulated, "1")
	action["sensitivity_rank"] = "0"
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action,
		ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "sensitivity_rank") {
		t.Fatalf("forged rank accepted: %s", result.Reason)
	}
	_, result, err = Act(&Ledger{}, []Delegation{delegation},
		sensitivityAction("top_secret", "1"), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "unknown sensitivity tier") {
		t.Fatalf("unknown tier accepted: %s", result.Reason)
	}
}
