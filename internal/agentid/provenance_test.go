package agentid

import (
	"strings"
	"testing"

	"github.com/rajat397/agentid/attest"
)

func provenanceProfile(t *testing.T) Profile {
	t.Helper()
	document := ExampleProfile().Document()
	document["require_trusted_provenance"] = true
	profile, err := ProfileFromMap(document)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func provenanceDelegation(t *testing.T) (Delegation, []byte) {
	t.Helper()
	signer, pub := newSigner(t, "provenance_key")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z", DelegationOptions{
			Signer: signer, NoPQ: true,
			Attestor: attest.DevAttestor{
				SPIFFEID:  "spiffe://example.trust/agent/provenance",
				PublicKey: subPubBytes(t, signer),
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	return delegation, pub
}

func TestProvenanceLattice(t *testing.T) {
	tracker := NewProvenanceTracker()
	if tracker.Value() != ProvenanceUntrusted {
		t.Fatal("missing provenance must start untrusted")
	}
	tracker.Observe(ProvenanceTrusted)
	tracker.Observe(ProvenanceTrusted)
	if tracker.Value() != ProvenanceTrusted {
		t.Fatal("all-trusted inputs should stay trusted")
	}
	tracker.Observe(ProvenanceUntrusted)
	if tracker.Value() != ProvenanceUntrusted {
		t.Fatal("one untrusted input must taint the action")
	}
}

func TestUntrustedProvenanceRequiresAcknowledgement(t *testing.T) {
	delegation, pub := provenanceDelegation(t)
	profile := provenanceProfile(t)
	action := testAction()

	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action, profile, pub,
		ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "indeterminate" {
		t.Fatalf("untrusted action was not gated: %s", result.Reason)
	}
	found := false
	for _, raw := range result.Obligations {
		if stringField(asMap(raw), "type") == "cosign_untrusted" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing cosign_untrusted obligation: %+v", result.Obligations)
	}

	approval := map[string]any{
		"id": "apr_prov", "delegation_id": delegation.ID,
		"action": "support.ticket.resolve", "approver": "usr", "nonce": "n1",
		"acknowledges_untrusted": true,
	}
	digest, err := EnvelopeDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	approval["envelope_digest"] = digest
	receipt, allowed, err := Act(&Ledger{}, []Delegation{delegation}, action, profile, pub,
		ActOptions{Approval: approval})
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Outcome != "valid" {
		t.Fatalf("acknowledged action rejected: %s", allowed.Reason)
	}
	discharged := false
	for _, raw := range receipt.Decision["obligations"].([]any) {
		obligation := asMap(raw)
		if stringField(obligation, "type") == "cosign_untrusted" &&
			stringField(obligation, "status") == "discharged" {
			discharged = true
		}
	}
	if !discharged {
		t.Fatal("approval did not discharge the provenance obligation")
	}

	missingAck := map[string]any{}
	for key, value := range approval {
		missingAck[key] = value
	}
	delete(missingAck, "acknowledges_untrusted")
	_, denied, err := Act(&Ledger{}, []Delegation{delegation}, action, profile, pub,
		ActOptions{Approval: missingAck})
	if err != nil {
		t.Fatal(err)
	}
	if denied.Outcome != "invalid" || !strings.Contains(denied.Reason, "acknowledge") {
		t.Fatalf("approval without acknowledgement accepted: %s", denied.Reason)
	}
}

func TestTrustedProvenancePasses(t *testing.T) {
	delegation, pub := provenanceDelegation(t)
	action := testAction()
	action["provenance"] = ProvenanceTrusted
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, action,
		provenanceProfile(t), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("trusted action rejected: %s", result.Reason)
	}
}

func asMap(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}
