package agentid

import (
	"strings"
	"testing"
)

func TestCombineDenyOverridesAndImplicitDeny(t *testing.T) {
	valid := Decision{Outcome: "valid", Reason: "within constraints"}
	indeterminate := Decision{Outcome: "indeterminate", Reason: "needs approval"}
	invalid := Decision{Outcome: "invalid", Reason: "over cap"}

	if got := Combine([]Decision{valid, invalid, indeterminate}); got.Outcome != "invalid" ||
		got.Reason != "over cap" {
		t.Fatalf("deny did not dominate: %+v", got)
	}
	if got := Combine([]Decision{valid, indeterminate}); got.Outcome != "indeterminate" ||
		got.Reason != "needs approval" {
		t.Fatalf("indeterminate did not dominate: %+v", got)
	}
	if got := Combine(nil); got.Outcome != "invalid" ||
		!strings.Contains(got.Reason, "implicit deny") {
		t.Fatalf("empty policy set was not denied: %+v", got)
	}
}

func TestCombineCanonicalObligationUnion(t *testing.T) {
	a := map[string]any{"type": "cosign_above", "value": "500"}
	b := map[string]any{"type": "cosign_untrusted"}
	first := Combine([]Decision{
		{Outcome: "valid", Obligations: []any{b, a}},
		{Outcome: "valid", Obligations: []any{a}},
	})
	second := Combine([]Decision{
		{Outcome: "valid", Obligations: []any{a, b}},
	})
	if len(first.Obligations) != 2 || len(second.Obligations) != 2 {
		t.Fatalf("obligation union failed: %+v / %+v", first, second)
	}
	left, _ := CanonicalJSON(first.Obligations)
	right, _ := CanonicalJSON(second.Obligations)
	if string(left) != string(right) {
		t.Fatalf("obligation order depends on input order: %s vs %s", left, right)
	}
}

func policyProfiles(t *testing.T) (Profile, Profile, Profile) {
	t.Helper()
	provenanceDoc := ExampleProfile().Document()
	provenanceDoc["require_trusted_provenance"] = true
	provenance, err := ProfileFromMap(provenanceDoc)
	if err != nil {
		t.Fatal(err)
	}
	predicateDoc := ExampleProfile().Document()
	predicateDoc["predicates"] = []any{"eq"}
	restrictive, err := ProfileFromMap(predicateDoc)
	if err != nil {
		t.Fatal(err)
	}
	return ExampleProfile(), provenance, restrictive
}

func TestEvaluatePolicySetCombining(t *testing.T) {
	signer, pub := newSigner(t, "combining_signer")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	base, provenance, restrictive := policyProfiles(t)
	chain := []Delegation{delegation}

	indeterminate, err := EvaluatePolicySet(chain, testAction(),
		[]Profile{base, provenance}, pub, ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if indeterminate.Outcome != "indeterminate" {
		t.Fatalf("provenance gate lost in policy set: %+v", indeterminate)
	}
	action := testAction()
	action["provenance"] = ProvenanceTrusted
	allowed, err := EvaluatePolicySet(chain, action, []Profile{base, provenance}, pub,
		ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Outcome != "valid" {
		t.Fatalf("valid policy set rejected: %+v", allowed)
	}
	denied, err := EvaluatePolicySet(chain, action, []Profile{base, restrictive}, pub,
		ValidationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Outcome != "invalid" {
		t.Fatalf("deny did not dominate in policy set: %+v", denied)
	}
}

func TestActWithPolicySetAndEvidenceBundle(t *testing.T) {
	signer, pub := newSigner(t, "combining_act_signer")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	base, provenance, _ := policyProfiles(t)
	action := testAction()
	action["provenance"] = ProvenanceTrusted
	ledger := &Ledger{}
	receipt, result, err := Act(ledger, []Delegation{delegation}, action, base, pub,
		ActOptions{Signer: signer, ExtraProfiles: []Profile{provenance}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("policy-set action rejected: %+v", result)
	}
	wantDigest, err := PolicySetDigest([]Profile{base, provenance})
	if err != nil {
		t.Fatal(err)
	}
	if stringField(receipt.Decision, "profile_digest") != wantDigest {
		t.Fatal("receipt does not name the policy-set digest")
	}
	bundle, err := BuildEvidenceBundle("default", ledger, []Delegation{delegation},
		base, nil, nil, signer.PublicKeys(), provenance)
	if err != nil {
		t.Fatal(err)
	}
	if problems := VerifyEvidenceBundle(bundle); len(problems) > 0 {
		t.Fatalf("policy-set bundle failed: %v", problems)
	}
}

func TestUnsupportedCombiningAlgorithmFails(t *testing.T) {
	signer, pub := newSigner(t, "combining_fail_signer")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, NoPQ: true})
	if err != nil {
		t.Fatal(err)
	}
	document := ExampleProfile().Document()
	document["combining"] = "permit-overrides"
	profile, err := ProfileFromMap(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluatePolicySet([]Delegation{delegation}, testAction(),
		[]Profile{profile}, pub, ValidationOptions{}); err == nil {
		t.Fatal("unsupported combining algorithm accepted")
	}
}
