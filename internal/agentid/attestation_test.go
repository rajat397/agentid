package agentid

import (
	"strings"
	"testing"
	"time"

	"github.com/rajat397/agentid/attest"
)

type staticAttestor struct{ attestation attest.Attestation }

func (s staticAttestor) Attest() (attest.Attestation, error) { return s.attestation, nil }

func attestedDelegation(t *testing.T, attestor attest.Attestor, actorKey []byte) (Delegation, []byte) {
	t.Helper()
	signer, pub := newSigner(t, "attestation_signer")
	delegation, err := CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr"}, "agent",
		testConstraints(), "2030-01-01T00:00:00Z", DelegationOptions{
			Signer: signer, Attestor: attestor, ActorPublicPEM: actorKey,
		})
	if err != nil {
		t.Fatal(err)
	}
	return delegation, pub
}

func TestDevAttestationPassesAndIsRecordedOnReceipt(t *testing.T) {
	signer, _ := newSigner(t, "attested_agent")
	actorKey := subPubBytes(t, signer)
	delegation, pub := attestedDelegation(t, attest.DevAttestor{
		SPIFFEID: "spiffe://example.trust/agent/attested", PublicKey: actorKey,
	}, actorKey)
	if delegation.Attestation == nil {
		t.Fatal("attestation missing from delegation")
	}
	receipt, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("attested action rejected: %s", result.Reason)
	}
	if stringField(receipt.Actor, "attestation_digest") == "" {
		t.Fatal("receipt does not bind the attestation")
	}
}

func TestExpiredAttestationIsDenied(t *testing.T) {
	signer, _ := newSigner(t, "expired_agent")
	actorKey := subPubBytes(t, signer)
	delegation, pub := attestedDelegation(t, staticAttestor{attestation: attest.Attestation{
		SPIFFEID:         "spiffe://example.trust/agent/expired",
		CredentialDigest: attest.CredentialDigest(actorKey),
		TrustDomain:      "example.trust",
		ValidUntil:       "2020-01-01T00:00:00Z",
		Evidence:         "static test attestor",
	}}, actorKey)
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "attestation expired") {
		t.Fatalf("expired attestation accepted: %s", result.Reason)
	}
}

func TestAttestationCredentialMismatchIsDenied(t *testing.T) {
	signer, _ := newSigner(t, "mismatch_agent")
	actorKey := subPubBytes(t, signer)
	other, _ := newSigner(t, "other_key")
	delegation, pub := attestedDelegation(t, staticAttestor{attestation: attest.Attestation{
		SPIFFEID:         "spiffe://example.trust/agent/mismatch",
		CredentialDigest: attest.CredentialDigest(subPubBytes(t, other)),
		TrustDomain:      "example.trust",
		ValidUntil:       time.Now().UTC().Add(time.Hour).Format(timeLayout),
		Evidence:         "static test attestor",
	}}, actorKey)
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "credential digest") {
		t.Fatalf("attestation with wrong credential accepted: %s", result.Reason)
	}
}

func TestAttestationRoundTripsThroughEvidenceBundle(t *testing.T) {
	signer, _ := newSigner(t, "bundle_agent")
	actorKey := subPubBytes(t, signer)
	delegation, _ := attestedDelegation(t, attest.DevAttestor{
		SPIFFEID: "spiffe://example.trust/agent/bundle", PublicKey: actorKey,
	}, actorKey)
	data, err := CanonicalJSON(delegation.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := DelegationFromMap(AsMap(value))
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.Attestation == nil || rebuilt.Attestation.SPIFFEID != delegation.Attestation.SPIFFEID {
		t.Fatalf("attestation lost in bundle: %+v", rebuilt.Attestation)
	}
}
