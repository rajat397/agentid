package agentid

import (
	"errors"
)

// ApprovalBody is the exact payload an approver signs. Key material and the
// signature itself are excluded so they cannot sign themselves.
func ApprovalBody(approval map[string]any) map[string]any {
	body := map[string]any{}
	for key, value := range approval {
		if key == "signature" || key == "approver_keys" {
			continue
		}
		body[key] = value
	}
	return body
}

// SignApproval attaches an ES256/ML-DSA signature and the approver's public
// key material. The agent cannot forge or modify an approval without breaking
// this binding.
func SignApproval(approval map[string]any, signer Signer) (map[string]any, error) {
	signature, err := signer.Sign(ApprovalBody(approval))
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for key, value := range approval {
		out[key] = value
	}
	out["signature"] = signature.toMap()
	out["approver_keys"] = map[string]any{
		signature.Kid: signer.PublicKeys()[signature.Kid],
	}
	return out, nil
}

// VerifyApprovalSignature checks an attached signature when present.
func VerifyApprovalSignature(approval map[string]any) error {
	raw := AsMap(approval["signature"])
	if raw == nil {
		return errors.New("approval has no approver signature")
	}
	signature := signatureFromMap(raw)
	material := stringValue(AsMap(approval["approver_keys"])[signature.Kid])
	if material == "" {
		return errors.New("approval signer key is not published")
	}
	if !VerifySignature(signature.Alg, material,
		ApprovalBody(approval), signature.Value) {
		return errors.New("approval signature invalid")
	}
	return nil
}
