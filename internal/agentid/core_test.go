package agentid

import (
	"encoding/json"
	"strings"
	"testing"
)

func newSigner(t *testing.T, kid string) (*DevSigner, []byte) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewDevSigner(priv, pub, kid)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pub
}

func testConstraints() map[string]any {
	return map[string]any{
		"permissions": []any{map[string]any{"action": "support.ticket.resolve", "system": "zendesk"}},
		"predicates": []any{
			map[string]any{"type": "in", "path": "/attributes/region", "values": []any{"eu", "us"}},
			map[string]any{"type": "max", "path": "/attributes/count", "value": "50"},
		},
	}
}

func testAction() map[string]any {
	return map[string]any{
		"action": "support.ticket.resolve", "system": "zendesk",
		"resource_type": "ticket", "resource_id": "t1",
		"region": "eu", "count": "5",
	}
}

func TestGoCreatesSignedChainAndReceipts(t *testing.T) {
	rootSigner, rootPub := newSigner(t, "root_key")
	agentSigner, agentPub := newSigner(t, "agent_key")
	subSigner, _ := newSigner(t, "sub_key")

	subject := map[string]any{"type": "human", "id": "oidc|acme-retail|usr_8842"}
	root, err := CreateDelegation(nil, subject, "agent", testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: rootSigner, ActorPublicPEM: agentPub})
	if err != nil {
		t.Fatal(err)
	}
	child, err := CreateDelegation(nil, subject, "sub-agent", testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: agentSigner, Parent: &root, ActorPublicPEM: subPubBytes(t, subSigner)})
	if err != nil {
		t.Fatal(err)
	}
	grandchild, err := CreateDelegation(nil, subject, "worker", testConstraints(), "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: subSigner, Parent: &child})
	if err != nil {
		t.Fatal(err)
	}

	ledger := &Ledger{}
	receipt, result, err := Act(ledger, []Delegation{root, child, grandchild}, testAction(),
		ExampleProfile(), rootPub, ActOptions{Signer: subSigner})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "valid" {
		t.Fatalf("outcome: %s (%s)", result.Outcome, result.Reason)
	}
	if receipt.Signature == nil || receipt.Signature.Kid != "sub_key" {
		t.Fatalf("receipt not signed by current signer: %+v", receipt.Signature)
	}
	if problems := ledger.VerifyChain(ledger.SignerKeys); len(problems) > 0 {
		t.Fatalf("chain verification: %v", problems)
	}
}

func subPubBytes(t *testing.T, signer Signer) []byte {
	t.Helper()
	pem, err := signer.PublicKey(signer.Kid())
	if err != nil {
		t.Fatal(err)
	}
	return []byte(pem)
}

func TestReceiptSignatureTamperDetected(t *testing.T) {
	signer, pub := newSigner(t, "tamper_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	receipt, _, err := Act(ledger, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature.Value = "tampered"
	problems := ledger.VerifyChain(ledger.SignerKeys)
	if len(problems) == 0 || !strings.Contains(problems[0], "signature") {
		t.Fatalf("tampered signature accepted: %v", problems)
	}
}

func TestAttenuationAtCreation(t *testing.T) {
	signer, _ := newSigner(t, "attenuation_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	parent, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer,
			ActorPublicPEM: subPubBytes(t, signer)})
	if err != nil {
		t.Fatal(err)
	}
	narrow := map[string]any{
		"permissions": []any{map[string]any{"action": "support.ticket.resolve", "system": "zendesk"}},
		"predicates": []any{
			map[string]any{"type": "in", "path": "/attributes/region", "values": []any{"eu"}},
			map[string]any{"type": "max", "path": "/attributes/count", "value": "25"},
		},
	}
	if _, err := CreateDelegation(nil, subject, "child", narrow, "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, Parent: &parent}); err != nil {
		t.Fatalf("narrowed child rejected: %v", err)
	}
	wide := map[string]any{
		"permissions": []any{map[string]any{"action": "support.ticket.resolve", "system": "zendesk"}},
		"predicates": []any{
			map[string]any{"type": "in", "path": "/attributes/region", "values": []any{"eu", "apac"}},
			map[string]any{"type": "max", "path": "/attributes/count", "value": "50"},
		},
	}
	if _, err := CreateDelegation(nil, subject, "child", wide, "2030-01-01T00:00:00Z",
		DelegationOptions{Signer: signer, Parent: &parent}); err == nil {
		t.Fatal("widened child was accepted")
	}
}

type pqStubSigner struct {
	Signer
}

func (s pqStubSigner) Sign(payload any) (Signature, error) {
	signature, err := s.Signer.Sign(payload)
	if err != nil {
		return Signature{}, err
	}
	signature.Alg = "ML-DSA-65"
	signature.Kid = "pq_key_stub"
	return signature, nil
}

func TestDualSignCarriesTwoAlgorithms(t *testing.T) {
	signer, _ := newSigner(t, "es_key")
	stub := pqStubSigner{Signer: signer}
	subject := map[string]any{"type": "human", "id": "usr"}
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	receipt, _, err := Act(ledger, []Delegation{delegation}, testAction(),
		ExampleProfile(), subPubBytes(t, signer), ActOptions{
			Signer: signer, ExtraSigners: []Signer{stub},
		})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Signature.Alg != "ES256" || len(receipt.Signatures) != 2 {
		t.Fatalf("unexpected signatures: %+v %+v", receipt.Signature, receipt.Signatures)
	}
	if receipt.Signatures[1].Alg != "ML-DSA-65" {
		t.Fatalf("PQ signature missing: %+v", receipt.Signatures)
	}
}

func TestStatusLookupGuard(t *testing.T) {
	signer, pub := newSigner(t, "status_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	idx := 0
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer, StatusIdx: &idx})
	if err != nil {
		t.Fatal(err)
	}
	_, result, err := Act(&Ledger{}, []Delegation{delegation}, testAction(),
		ExampleProfile(), pub, ActOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "invalid" || !strings.Contains(result.Reason, "lookup") {
		t.Fatalf("missing lookup was not fail-closed: %s", result.Reason)
	}
}

func TestNilSlicesCanonicalizeAsNullAndSurviveRoundTrip(t *testing.T) {
	data, err := CanonicalJSON(map[string]any{"obligations": []any(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"obligations":null}` {
		t.Fatalf("nil slice canonicalized as %s", data)
	}
	signer, pub := newSigner(t, "roundtrip_key")
	subject := map[string]any{"type": "human", "id": "usr"}
	delegation, err := CreateDelegation(nil, subject, "agent", testConstraints(),
		"2030-01-01T00:00:00Z", DelegationOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	receipt, _, err := Act(ledger, []Delegation{delegation}, map[string]any{
		"action": "support.ticket.resolve", "system": "zendesk",
		"region": "apac", "count": "1",
	}, ExampleProfile(), pub, ActOptions{Signer: signer})
	if err != nil {
		t.Fatal(err)
	}
	before, err := receipt.Hash()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(receipt.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	value, err := DecodeJSON(stored)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := ReceiptFromMap(AsMap(value))
	after, err := reloaded.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("receipt hash changed across JSON round trip: %s -> %s", before, after)
	}
}
