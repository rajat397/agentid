package agentid

import (
	"fmt"

	"github.com/rajat397/agentid/attest"
)

// Delegation is one signed hop of the authority chain.
type Delegation struct {
	ID                 string
	Subject            map[string]any
	Actor              map[string]any
	ParentDelegationID any
	ChainDepth         int
	Constraints        map[string]any
	IssuedAt           string
	ExpiresAt          string
	Signature          Signature
	Signatures         []Signature
	Issuer             map[string]any
	StatusList         map[string]any
	Attestation        *attest.Attestation
	Draft              bool
	SignerKeys         map[string]string
}

// UnsignedBody is the exact signed payload, excluding the signature.
func (d Delegation) UnsignedBody() map[string]any {
	body := map[string]any{
		"actor":                d.Actor,
		"chain_depth":          d.ChainDepth,
		"constraints":          d.Constraints,
		"expires_at":           d.ExpiresAt,
		"id":                   d.ID,
		"issued_at":            d.IssuedAt,
		"parent_delegation_id": d.ParentDelegationID,
		"subject":              d.Subject,
	}
	if d.Issuer != nil {
		body["issuer"] = d.Issuer
	}
	if d.StatusList != nil {
		body["status_list"] = d.StatusList
	}
	if d.Attestation != nil {
		body["attestation"] = d.Attestation
	}
	if d.Draft {
		body["draft"] = true
	}
	return body
}

// DelegationFromMap reconstructs a delegation from a verified vector or store.
func DelegationFromMap(raw map[string]any) (Delegation, error) {
	if raw == nil {
		return Delegation{}, fmt.Errorf("delegation must be an object")
	}
	depth := 0
	if value, ok := raw["chain_depth"]; ok {
		depth = intValue(value)
	}
	return Delegation{
		ID:                 stringField(raw, "id"),
		Subject:            AsMap(raw["subject"]),
		Actor:              AsMap(raw["actor"]),
		ParentDelegationID: raw["parent_delegation_id"],
		ChainDepth:         depth,
		Constraints:        AsMap(raw["constraints"]),
		IssuedAt:           stringField(raw, "issued_at"),
		ExpiresAt:          stringField(raw, "expires_at"),
		Signature:          signatureFromMap(raw["signature"]),
		Signatures:         signaturesFromMap(raw["signatures"]),
		Issuer:             AsMap(raw["issuer"]),
		StatusList:         AsMap(raw["status_list"]),
		Attestation:        attestationFromMap(raw["attestation"]),
		Draft:              raw["draft"] == true,
	}, nil
}

// Receipt is the signed, hash-chained evidence artifact for one action.
type Receipt struct {
	ID           string
	IssuedAt     string
	Fleet        string
	Actor        map[string]any
	DelegationID string
	Action       string
	Resource     map[string]any
	Decision     map[string]any
	Outcome      map[string]any
	ActionType   string
	PrevHash     string
	SignatureAlg string
	Signature    *Signature
	Signatures   []Signature
}

// Body is the signed payload (signatures are deliberately excluded).
func (r Receipt) Body() map[string]any {
	return map[string]any{
		"action":        r.Action,
		"action_type":   r.ActionType,
		"actor":         r.Actor,
		"decision":      r.Decision,
		"delegation_id": r.DelegationID,
		"fleet":         r.Fleet,
		"outcome":       r.Outcome,
		"prev_hash":     r.PrevHash,
		"resource":      r.Resource,
	}
}

// Hash is the content-address of the receipt body.
func (r Receipt) Hash() (string, error) {
	data, err := CanonicalJSON(r.Body())
	if err != nil {
		return "", err
	}
	return DigestSHA256(data), nil
}

// PersonalDataRefs returns the opaque subject references touched by the receipt.
func (r Receipt) PersonalDataRefs() []string {
	attributes := AsMap(AsMap(r.Resource)["attributes"])
	refs, _ := attributes["personal_data_refs"].([]any)
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		out = append(out, fmt.Sprint(ref))
	}
	return out
}

// ValidationResult mirrors the mandate draft's valid/invalid/indeterminate.
type ValidationResult struct {
	Outcome              string
	Reason               string
	Obligations          []any
	ConstraintsEvaluated []any
}

// ReceiptFromMap reconstructs a receipt from stored JSON.
func ReceiptFromMap(raw map[string]any) Receipt {
	receipt := Receipt{
		ID:           stringField(raw, "id"),
		IssuedAt:     stringField(raw, "issued_at"),
		Fleet:        stringField(raw, "fleet"),
		Actor:        AsMap(raw["actor"]),
		DelegationID: stringField(raw, "delegation_id"),
		Action:       stringField(raw, "action"),
		Resource:     AsMap(raw["resource"]),
		Decision:     AsMap(raw["decision"]),
		Outcome:      AsMap(raw["outcome"]),
		ActionType:   stringField(raw, "action_type"),
		PrevHash:     stringField(raw, "prev_hash"),
		SignatureAlg: stringField(raw, "signature_alg"),
	}
	if signature := AsMap(raw["signature"]); signature != nil {
		value := signatureFromMap(signature)
		receipt.Signature = &value
	}
	receipt.Signatures = signaturesFromMap(raw["signatures"])
	return receipt
}

// ToMap returns the stored JSON form of a receipt (lowercase field names).
func (r Receipt) ToMap() map[string]any {
	out := map[string]any{
		"id": r.ID, "issued_at": r.IssuedAt, "fleet": r.Fleet,
		"actor": r.Actor, "delegation_id": r.DelegationID, "action": r.Action,
		"resource": r.Resource, "decision": r.Decision, "outcome": r.Outcome,
		"action_type": r.ActionType, "prev_hash": r.PrevHash,
		"signature_alg": r.SignatureAlg,
	}
	if r.Signature != nil {
		out["signature"] = map[string]any{
			"alg": r.Signature.Alg, "kid": r.Signature.Kid, "value": r.Signature.Value,
		}
	}
	if r.Signatures != nil {
		items := []any{}
		for _, signature := range r.Signatures {
			items = append(items, map[string]any{
				"alg": signature.Alg, "kid": signature.Kid, "value": signature.Value,
			})
		}
		out["signatures"] = items
	}
	return out
}

func signaturesFromMap(value any) []Signature {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]Signature, 0, len(items))
	for _, item := range items {
		out = append(out, signatureFromMap(item))
	}
	return out
}

func signaturesToMap(signatures []Signature) []any {
	out := []any{}
	for _, signature := range signatures {
		out = append(out, signature.toMap())
	}
	return out
}

// SignerKeysToMap exports the verified public-key registry for an artifact.
func SignerKeysToMap(keys map[string]string) map[string]any {
	out := map[string]any{}
	for kid, material := range keys {
		out[kid] = material
	}
	return out
}

// ToMap returns the stored JSON form of a delegation, including extra
// signatures and the public-key registry needed for offline verification.
func (d Delegation) ToMap() map[string]any {
	out := map[string]any{
		"id": d.ID, "subject": d.Subject, "actor": d.Actor,
		"parent_delegation_id": d.ParentDelegationID,
		"chain_depth":          d.ChainDepth, "constraints": d.Constraints,
		"issued_at": d.IssuedAt, "expires_at": d.ExpiresAt,
		"signature": d.Signature.toMap(),
	}
	if d.Issuer != nil {
		out["issuer"] = d.Issuer
	}
	if d.StatusList != nil {
		out["status_list"] = d.StatusList
	}
	if d.Draft {
		out["draft"] = true
	}
	if d.Attestation != nil {
		out["attestation"] = map[string]any{
			"spiffe_id":         d.Attestation.SPIFFEID,
			"credential_digest": d.Attestation.CredentialDigest,
			"trust_domain":      d.Attestation.TrustDomain,
			"valid_until":       d.Attestation.ValidUntil,
			"evidence":          d.Attestation.Evidence,
		}
	}
	if d.Signatures != nil {
		out["signatures"] = signaturesToMap(d.Signatures)
	}
	if d.SignerKeys != nil {
		out["signer_keys"] = SignerKeysToMap(d.SignerKeys)
	}
	return out
}

func attestationFromMap(value any) *attest.Attestation {
	raw := AsMap(value)
	if raw == nil {
		return nil
	}
	return &attest.Attestation{
		SPIFFEID:         stringField(raw, "spiffe_id"),
		CredentialDigest: stringField(raw, "credential_digest"),
		TrustDomain:      stringField(raw, "trust_domain"),
		ValidUntil:       stringField(raw, "valid_until"),
		Evidence:         stringField(raw, "evidence"),
	}
}
