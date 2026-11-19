package agentid

import "testing"

func versionedChain(t *testing.T, parentVersion, childVersion AgentVersion) ([]Delegation, []byte) {
	t.Helper()
	rootSigner, rootPub := newSigner(t, "version_root")
	agentSigner, agentPub := newSigner(t, "version_agent")
	subject := map[string]any{"type": "human", "id": "usr"}
	parent, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{
			Signer: rootSigner, NoPQ: true, Version: &parentVersion,
			ActorPublicPEM: agentPub,
		})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CreateDelegation(nil, subject, "sub-agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{
			Signer: agentSigner, NoPQ: true, Version: &childVersion, Parent: &parent,
		})
	if err != nil {
		t.Fatal(err)
	}
	return []Delegation{parent, child}, rootPub
}

func TestAgentVersionDriftIsAnObligation(t *testing.T) {
	chain, pub := versionedChain(t,
		AgentVersion{Build: "v1", Engine: "runtime-a", Model: "m1"},
		AgentVersion{Build: "v2", Engine: "runtime-a", Model: "m2"})
	ledger := &Ledger{}
	receipt, result, err := Act(ledger, chain, testAction(), ExampleProfile(), pub,
		ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("versioned chain rejected: %+v", result)
	}
	drift := false
	for _, raw := range result.Obligations {
		if stringField(asMap(raw), "type") == "agent_version_drift" {
			drift = true
		}
	}
	if !drift {
		t.Fatalf("version drift not noted: %+v", result.Obligations)
	}
	version := AsMap(receipt.Actor["version"])
	if stringField(version, "build") != "v2" || stringField(version, "model") != "m2" {
		t.Fatalf("receipt does not record leaf version: %+v", receipt.Actor)
	}
}

func TestStableVersionHasNoDrift(t *testing.T) {
	version := AgentVersion{Build: "v1", Engine: "runtime-a"}
	chain, pub := versionedChain(t, version, version)
	_, result, err := Act(&Ledger{}, chain, testAction(), ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range result.Obligations {
		if stringField(asMap(raw), "type") == "agent_version_drift" {
			t.Fatal("stable version produced drift obligation")
		}
	}
}
