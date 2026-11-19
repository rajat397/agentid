// Command pqbench measures the cost of adding ML-DSA-65 dual-signatures to
// receipts and delegations. It runs only with Go 1.27+ (crypto/mldsa).
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"crypto/mldsa"

	"github.com/rajat397/agentid/internal/agentid"
)

const iterations = 2000

func main() {
	esPriv, esPub, err := agentid.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	esKey, err := agentid.ParsePrivatePEM(esPriv)
	if err != nil {
		panic(err)
	}
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		panic(err)
	}
	payload := map[string]any{
		"action": "support.ticket.resolve", "system": "zendesk",
		"resource": map[string]any{"type": "ticket", "id": "t1"},
		"attributes": map[string]any{"region": "eu", "count": "5"},
		"nonce": "bench-1",
	}
	data, err := agentid.CanonicalJSON(payload)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(data)

	esSignStart := time.Now()
	var esSig string
	for i := 0; i < iterations; i++ {
		esSig, err = agentid.SignRaw(esKey, data)
		if err != nil {
			panic(err)
		}
	}
	esSign := time.Since(esSignStart) / iterations

	esPubKey, err := agentid.ParsePublicPEM(esPub)
	if err != nil {
		panic(err)
	}
	esVerifyStart := time.Now()
	for i := 0; i < iterations; i++ {
		if !agentid.VerifyRaw(esPubKey, data, esSig) {
			panic("ES256 verification failed")
		}
	}
	esVerify := time.Since(esVerifyStart) / iterations

	mlSignStart := time.Now()
	var mlSig []byte
	for i := 0; i < iterations; i++ {
		mlSig, err = mlKey.Sign(rand.Reader, data, nil)
		if err != nil {
			panic(err)
		}
	}
	mlSign := time.Since(mlSignStart) / iterations

	mlPub := mlKey.PublicKey().Bytes()
	mlVerifyStart := time.Now()
	for i := 0; i < iterations; i++ {
		if err := mldsa.Verify(mustPublic(mlPub), data, mlSig, nil); err != nil {
			panic("ML-DSA verification failed: " + err.Error())
		}
	}
	mlVerify := time.Since(mlVerifyStart) / iterations

	esSigBytes, _ := base64.RawURLEncoding.DecodeString(esSig)
	esPubDER, _ := json.Marshal(string(esPub))

	esSigner, err := agentid.NewDevSigner(esPriv, esPub, "bench_es_key")
	if err != nil {
		panic(err)
	}
	delegation, err := agentid.CreateDelegation(nil,
		map[string]any{"type": "human", "id": "usr_bench"}, "bench-agent",
		map[string]any{"permissions": []any{map[string]any{
			"action": "support.ticket.resolve", "system": "zendesk"}}},
		"2030-01-01T00:00:00Z", agentid.DelegationOptions{Signer: esSigner})
	if err != nil {
		panic(err)
	}
	action := map[string]any{
		"action": "support.ticket.resolve", "system": "zendesk",
		"resource_type": "ticket", "resource_id": "t1",
		"region": "eu", "count": "5", "personal_data_refs": []any{"cust_1"},
	}
	esOnlyLedger := &agentid.Ledger{}
	esOnlyReceipt, _, err := agentid.Act(esOnlyLedger, []agentid.Delegation{delegation},
		action, agentid.ExampleProfile(), esPub, agentid.ActOptions{Signer: esSigner})
	if err != nil {
		panic(err)
	}
	dualLedger := &agentid.Ledger{}
	dualReceipt, _, err := agentid.Act(dualLedger, []agentid.Delegation{delegation},
		action, agentid.ExampleProfile(), esPub,
		agentid.ActOptions{Signer: esSigner, ExtraSigners: []agentid.Signer{
			&benchPQSigner{key: mlKey, kid: "bench_pq_key"},
		}})
	if err != nil {
		panic(err)
	}
	esOnlyJSON, _ := json.Marshal(esOnlyReceipt.ToMap())
	dualReceiptJSON, _ := json.Marshal(dualReceipt.ToMap())

	receiptWithES := map[string]any{
		"decision": map[string]any{"signature": map[string]any{"alg": "ES256", "value": esSig}},
	}
	receiptDual := map[string]any{
		"decision": map[string]any{"signatures": []any{
			map[string]any{"alg": "ES256", "value": esSig},
			map[string]any{"alg": "ML-DSA-65", "value": base64.RawURLEncoding.EncodeToString(mlSig)},
		}},
	}
	esJSON, _ := json.Marshal(receiptWithES)
	dualJSON, _ := json.Marshal(receiptDual)

	fmt.Printf("toolchain: go1.27 crypto/mldsa (FIPS 204), parameter set ML-DSA-65\n")
	fmt.Printf("ES256 signature:    %d bytes; public key PEM: %d bytes\n", len(esSigBytes), len(esPubDER))
	fmt.Printf("ML-DSA-65 signature: %d bytes; public key: %d bytes\n", len(mlSig), len(mlPub))
	fmt.Printf("sign latency:   ES256 %v  ML-DSA-65 %v  (%.1fx)\n",
		esSign, mlSign, float64(mlSign)/float64(esSign))
	fmt.Printf("verify latency: ES256 %v  ML-DSA-65 %v  (%.1fx)\n",
		esVerify, mlVerify, float64(mlVerify)/float64(esVerify))
	fmt.Printf("receipt JSON: ES256 %d bytes  dual %d bytes  (+%d bytes, %.1fx)\n",
		len(esJSON), len(dualJSON), len(dualJSON)-len(esJSON),
		float64(len(dualJSON))/float64(len(esJSON)))
	fmt.Printf("real receipt JSON: ES256 %d bytes  dual %d bytes  (+%d bytes, %.1fx)\n",
		len(esOnlyJSON), len(dualReceiptJSON), len(dualReceiptJSON)-len(esOnlyJSON),
		float64(len(dualReceiptJSON))/float64(len(esOnlyJSON)))
	fmt.Printf("1M receipts: ES256 %.1f MB  dual %.1f MB\n",
		float64(len(esOnlyJSON))*1e6/1e6, float64(len(dualReceiptJSON))*1e6/1e6)
	fmt.Printf("canonical payload digest: %x\n", digest[:8])
}

func mustPublic(raw []byte) *mldsa.PublicKey {
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	if err != nil {
		panic(err)
	}
	return key
}

type benchPQSigner struct {
	key *mldsa.PrivateKey
	kid string
}

func (s *benchPQSigner) Kid() string { return s.kid }

func (s *benchPQSigner) Sign(payload any) (agentid.Signature, error) {
	data, err := agentid.CanonicalJSON(payload)
	if err != nil {
		return agentid.Signature{}, err
	}
	raw, err := s.key.Sign(rand.Reader, data, nil)
	if err != nil {
		return agentid.Signature{}, err
	}
	return agentid.Signature{Alg: "ML-DSA-65", Kid: s.kid,
		Value: base64.RawURLEncoding.EncodeToString(raw)}, nil
}

func (s *benchPQSigner) SignRaw(data []byte) (string, error) {
	raw, err := s.key.Sign(rand.Reader, data, nil)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *benchPQSigner) PublicKey(kid string) (string, error) {
	if kid != s.kid {
		return "", fmt.Errorf("unknown kid %q", kid)
	}
	return base64.RawURLEncoding.EncodeToString(s.key.PublicKey().Bytes()), nil
}

func (s *benchPQSigner) PublicKeys() map[string]string {
	return map[string]string{s.kid: base64.RawURLEncoding.EncodeToString(s.key.PublicKey().Bytes())}
}
