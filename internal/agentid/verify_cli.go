package agentid

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
)

// VerifySignedArtifact checks every signature in a crosstest artifact. It is
// the Go verifier for both classical and post-quantum signatures.
func VerifySignedArtifact(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var artifact map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&artifact); err != nil {
		return nil, err
	}
	keys := map[string]string{}
	for kid, material := range AsMap(artifact["signer_keys"]) {
		keys[kid] = stringValue(material)
	}
	if len(keys) == 0 {
		for kid, material := range AsMap(artifact["status_public_keys"]) {
			keys[kid] = stringValue(material)
		}
	}
	verified := []string{}
	primary := []struct {
		name string
		body any
		sig  any
	}{
		{"delegation", artifact["delegation_body"], artifact["delegation_sig_obj"]},
		{"receipt", artifact["receipt_body"], artifact["receipt_sig_obj"]},
	}
	for _, entry := range primary {
		signature := signatureFromMap(entry.sig)
		if signature.Value == "" || !VerifySignature(signature.Alg,
			keys[signature.Kid], entry.body, signature.Value) {
			return nil, errors.New(entry.name + " signature invalid")
		}
		verified = append(verified, signature.Alg)
	}
	extra := []struct {
		name string
		body any
		raw  []any
	}{
		{"delegation PQ", artifact["delegation_body"], asSliceSafe(artifact["delegation_extra"])},
		{"receipt PQ", artifact["receipt_body"], asSliceSafe(artifact["receipt_extra"])},
	}
	for _, group := range extra {
		for _, item := range group.raw {
			signature := signatureFromMap(item)
			if !VerifySignature(signature.Alg, keys[signature.Kid],
				group.body, signature.Value) {
				return nil, errors.New(group.name + " signature invalid")
			}
			verified = append(verified, signature.Alg)
		}
	}
	if token := stringField(artifact, "status_token"); token != "" {
		if _, err := VerifyStatusTokenAtIssuedTime(token, keys, 300); err != nil {
			return nil, errors.New("status token invalid: " + err.Error())
		}
	}
	return verified, nil
}

func asSliceSafe(value any) []any {
	if items, ok := value.([]any); ok {
		return items
	}
	return nil
}
