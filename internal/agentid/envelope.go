package agentid

import (
	"errors"
)

var reservedEnvelopeKeys = map[string]bool{
	"action": true, "system": true, "resource_type": true,
	"resource_id": true, "nonce": true, "external_ref": true,
	"stage": true,
}

// Envelope is the canonical unit of approval, validation and receipt.
type Envelope struct {
	Action     string
	System     string
	Resource   map[string]any
	Attributes map[string]any
	Nonce      any
	Stage      string
}

// BuildEnvelope projects a flat action request into the canonical envelope.
func BuildEnvelope(request map[string]any) (Envelope, error) {
	action, ok := request["action"].(string)
	if !ok || action == "" {
		return Envelope{}, errors.New("action envelope requires 'action'")
	}
	system, ok := request["system"].(string)
	if !ok || system == "" {
		return Envelope{}, errors.New("action envelope requires 'system'")
	}
	attributes := make(map[string]any)
	for key, value := range request {
		if !reservedEnvelopeKeys[key] {
			attributes[key] = value
		}
	}
	stage, _ := request["stage"].(string)
	return Envelope{
		Action: action,
		System: system,
		Stage:  stage,
		Resource: map[string]any{
			"type": request["resource_type"],
			"id":   request["resource_id"],
		},
		Attributes: attributes,
		Nonce:      request["nonce"],
	}, nil
}

// ToMap produces the exact structure hashed for envelope digests.
func (e Envelope) ToMap() map[string]any {
	out := map[string]any{
		"action":     e.Action,
		"system":     e.System,
		"resource":   e.Resource,
		"attributes": e.Attributes,
		"nonce":      e.Nonce,
	}
	if e.Stage != "" {
		out["stage"] = e.Stage
	}
	return out
}

// EnvelopeDigest is the content-address of a canonical action envelope.
func EnvelopeDigest(request map[string]any) (string, error) {
	envelope, err := BuildEnvelope(request)
	if err != nil {
		return "", err
	}
	data, err := CanonicalJSON(envelope.ToMap())
	if err != nil {
		return "", err
	}
	return DigestSHA256(data), nil
}
