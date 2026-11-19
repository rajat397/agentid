package agentid

import (
	"strings"
	"testing"
)

func stageConstraints(ceiling string) map[string]any {
	constraints := testConstraints()
	constraints["stage"] = ceiling
	return constraints
}

func stageDelegation(t *testing.T, ceiling string) (Delegation, []byte) {
	t.Helper()
	signer, pub := newSigner(t, "stage_key")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		stageConstraints(ceiling), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	return delegation, pub
}

func stageAction(stage string) map[string]any {
	action := testAction()
	action["stage"] = stage
	return action
}

func TestStageCeilingIsEnforced(t *testing.T) {
	delegation, pub := stageDelegation(t, StageRead)
	_, result, err := Act(&Ledger{}, []Delegation{delegation},
		stageAction(StageSideEffect), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "stage") {
		t.Fatalf("side effect passed a read-only grant: %s", result.Reason)
	}
	receipt, result, err := Act(&Ledger{}, []Delegation{delegation},
		stageAction(StageRead), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("read stage rejected: %s", result.Reason)
	}
	if stringField(receipt.Resource, "stage") != StageRead {
		t.Fatalf("receipt does not record the stage: %+v", receipt.Resource)
	}
}

func TestStageMissingFailsClosedWhenCeilingPresent(t *testing.T) {
	delegation, pub := stageDelegation(t, StageRead)
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "stage") {
		t.Fatalf("missing stage accepted: %s", result.Reason)
	}
}

func TestStageProfileAllowlist(t *testing.T) {
	delegation, pub := stageDelegation(t, StageSideEffect)
	document := ExampleProfile().Document()
	document["stage_allowlist"] = []any{StagePlan, StageRead}
	profile, err := ProfileFromMap(document)
	if err != nil {
		t.Fatal(err)
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation},
		stageAction(StageWrite), profile, pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "allowlist") {
		t.Fatalf("stage outside profile allowlist accepted: %s", result.Reason)
	}
}

func TestStageAttenuation(t *testing.T) {
	signer, _ := newSigner(t, "stage_attenuation")
	subject := map[string]any{"type": "human", "id": "usr"}
	parent, err := CreateDelegation(nil, subject, "agent", stageConstraints(StageRead),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateDelegation(nil, subject, "child", stageConstraints(StageWrite),
		"2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true, Parent: &parent}); err == nil {
		t.Fatal("child escalated the stage ceiling")
	}
	if _, err := CreateDelegation(nil, subject, "child", stageConstraints(StagePlan),
		"2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true, Parent: &parent}); err != nil {
		t.Fatalf("narrowed stage rejected: %v", err)
	}
}
