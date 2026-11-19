package agentid

import (
	"fmt"
	"time"
)

// ActOptions carries optional evidence into the action path.
type ActOptions struct {
	Fleet        string
	Approval     map[string]any
	At           string
	Revoked      map[string]bool
	Signer       Signer
	PQSigner     Signer
	ExtraSigners []Signer
	StatusLookup func(uri string, idx int) (int, error)
}

// Act validates an action, mints the receipt, and appends it to the ledger.
func Act(ledger *Ledger, chain []Delegation, action map[string]any,
	profile Profile, publicPEM []byte, opts ActOptions) (*Receipt, ValidationResult, error) {
	validationOpts := ValidationOptions{
		Ledger: ledger, Approval: opts.Approval, At: opts.At,
		Revoked: opts.Revoked, StatusLookup: opts.StatusLookup,
	}
	if opts.Signer != nil {
		validationOpts.PublicKeys = opts.Signer.PublicKeys()
	}
	result := Validate(chain, action, profile, publicPEM, validationOpts)

	previous := "0000000000000000000000000000000000000000000000000000000000000000"
	if len(ledger.Receipts) > 0 {
		hash, err := ledger.Receipts[len(ledger.Receipts)-1].Hash()
		if err != nil {
			return nil, ValidationResult{}, err
		}
		previous = hash
	}
	envelope, err := BuildEnvelope(action)
	if err != nil {
		return nil, ValidationResult{}, err
	}
	attributes := map[string]any{}
	for key, value := range envelope.Attributes {
		attributes[key] = value
	}
	refs, ok := action["personal_data_refs"].([]any)
	if !ok {
		refs = []any{}
	}
	attributes["personal_data_refs"] = refs
	amount := action["amount"]
	if amount == nil {
		amount = "0"
	}
	currency := action["currency"]
	if currency == nil {
		currency = "USD"
	}
	digest, err := EnvelopeDigest(action)
	if err != nil {
		return nil, ValidationResult{}, err
	}
	decision := map[string]any{
		"result":                "denied",
		"outcome":               result.Outcome,
		"reason":                result.Reason,
		"envelope_digest":       digest,
		"constraints_evaluated": result.ConstraintsEvaluated,
		"obligations":           result.Obligations,
	}
	if result.Outcome == "valid" {
		decision["result"] = "allowed"
	}
	fleet := opts.Fleet
	if fleet == "" {
		fleet = "marketing"
	}
	leaf := chain[len(chain)-1]
	receipt := &Receipt{
		IssuedAt: time.Now().UTC().Format(timeLayout),
		Fleet:    fleet,
		Actor: map[string]any{
			"spiffe_id":      stringField(leaf.Actor, "spiffe_id"),
			"agent_id":       stringField(leaf.Actor, "id"),
			"credential_kid": leaf.Signature.Kid,
		},
		DelegationID: leaf.ID,
		Action:       stringField(action, "action"),
		Resource: map[string]any{
			"type":       action["resource_type"],
			"id":         action["resource_id"],
			"attributes": attributes,
			"amount":     amount,
			"currency":   currency,
		},
		Decision: decision,
		Outcome: map[string]any{
			"status":       "blocked",
			"external_ref": action["external_ref"],
			"blocked":      result.Outcome != "valid",
		},
		ActionType:   "observed",
		PrevHash:     previous,
		SignatureAlg: "ES256",
	}
	if result.Outcome == "valid" {
		receipt.Outcome["status"] = "succeeded"
	}
	if opts.Signer != nil {
		signature, err := opts.Signer.Sign(receipt.Body())
		if err != nil {
			return nil, ValidationResult{}, fmt.Errorf("sign receipt: %w", err)
		}
		receipt.Signature = &signature
		ledger.RegisterKeys(opts.Signer.PublicKeys())

		extra := []Signer{}
		if profile.PQSign {
			pq := opts.PQSigner
			if pq == nil {
				pq, err = DefaultPQSigner()
				if err != nil {
					return nil, ValidationResult{}, fmt.Errorf("PQ signer: %w", err)
				}
			}
			extra = append(extra, pq)
			ledger.RegisterKeys(pq.PublicKeys())
		}
		extra = append(extra, opts.ExtraSigners...)
		for _, signer := range opts.ExtraSigners {
			ledger.RegisterKeys(signer.PublicKeys())
		}
		if len(extra) > 0 {
			signatures, err := DualSign(receipt.Body(), extra)
			if err != nil {
				return nil, ValidationResult{}, fmt.Errorf("dual-sign receipt: %w", err)
			}
			receipt.Signatures = signatures
		}
	}
	if err := ledger.Append(receipt); err != nil {
		return nil, ValidationResult{}, err
	}
	return receipt, result, nil
}
