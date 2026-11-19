package agentid

import (
	"errors"
)

// DelegationOptions controls creation of one signed authority hop.
type DelegationOptions struct {
	Parent         *Delegation
	ActorPublicPEM []byte
	IssuerID       string
	Signer         Signer
	StatusIdx      *int
	StatusURI      string
}

// CreateDelegation mints a signed, attenuating delegation hop.
func CreateDelegation(privatePEM []byte, subject map[string]any, actorID string,
	constraints map[string]any, expiresAt string, opts DelegationOptions) (Delegation, error) {
	if opts.Signer != nil && len(privatePEM) > 0 {
		return Delegation{}, errors.New("provide either private_pem or signer, not both")
	}
	if opts.Signer == nil && len(privatePEM) == 0 {
		return Delegation{}, errors.New("a private_pem or a signer is required")
	}
	var signerPublic []byte
	var err error
	if opts.Signer != nil {
		pem, err := opts.Signer.PublicKey(opts.Signer.Kid())
		if err != nil {
			return Delegation{}, err
		}
		signerPublic = []byte(pem)
	} else {
		key, err := ParsePrivatePEM(privatePEM)
		if err != nil {
			return Delegation{}, err
		}
		signerPublic, err = PublicPEMFromPrivate(key)
		if err != nil {
			return Delegation{}, err
		}
	}
	if opts.Parent != nil {
		if violation := AttenuationViolation(constraints, opts.Parent.Constraints); violation != "" {
			return Delegation{}, errors.New(violation)
		}
		pinned := stringField(opts.Parent.Actor, "verification_key")
		if pinned != "" {
			if pinned != string(signerPublic) {
				return Delegation{}, errors.New(
					"issuer key does not match parent's pinned actor verification_key")
			}
		}
	}

	issued := nowISO()
	spiffe := "spiffe://example.trust/agent/" + actorID
	parentID := ""
	if opts.Parent != nil {
		parentID = opts.Parent.ID
	}
	idMaterial, err := CanonicalJSON([]any{
		stringValue(AsMap(subject)["id"]), spiffe, issued, parentID,
	})
	if err != nil {
		return Delegation{}, err
	}
	id := "dlg_" + DigestSHA256(idMaterial)[:16]
	depth := 1
	if opts.Parent != nil {
		depth = opts.Parent.ChainDepth + 1
	}
	issuerID := opts.IssuerID
	if issuerID == "" {
		if opts.Parent != nil {
			issuerID = stringField(opts.Parent.Actor, "id")
		} else {
			issuerID = stringValue(AsMap(subject)["id"])
		}
	}
	issuer := map[string]any{"id": issuerID, "kid": KeyFingerprint(signerPublic)}
	actor := map[string]any{"type": "agent", "id": actorID, "spiffe_id": spiffe}
	if len(opts.ActorPublicPEM) > 0 {
		actor["verification_key"] = string(opts.ActorPublicPEM)
	}

	body := map[string]any{
		"actor":                actor,
		"chain_depth":          depth,
		"constraints":          constraints,
		"expires_at":           expiresAt,
		"id":                   id,
		"issued_at":            issued,
		"parent_delegation_id": parentID,
		"subject":              subject,
		"issuer":               issuer,
	}
	var statusList map[string]any
	if opts.StatusIdx != nil {
		uri := opts.StatusURI
		if uri == "" {
			uri = "https://example.invalid/status"
		}
		statusList = map[string]any{"idx": *opts.StatusIdx, "uri": uri}
		body["status_list"] = statusList
	}

	var signature Signature
	if opts.Signer != nil {
		signature, err = opts.Signer.Sign(body)
		if err != nil {
			return Delegation{}, err
		}
	} else {
		key, err := ParsePrivatePEM(privatePEM)
		if err != nil {
			return Delegation{}, err
		}
		value, err := Sign(key, body)
		if err != nil {
			return Delegation{}, err
		}
		signature = Signature{Alg: "ES256", Kid: stringValue(issuer["kid"]), Value: value}
	}
	return Delegation{
		ID: id, Subject: subject, Actor: actor, ParentDelegationID: parentID,
		ChainDepth: depth, Constraints: constraints, IssuedAt: issued,
		ExpiresAt: expiresAt, Signature: signature, Issuer: issuer,
		StatusList: statusList,
	}, nil
}

func nowISO() string {
	return dateTimeNow().Format(timeLayout)
}

// VerifyDelegation checks one hop's signature against a pinned public key.
func VerifyDelegation(publicPEM []byte, delegation Delegation) bool {
	key, err := ParsePublicPEM(publicPEM)
	if err != nil {
		return false
	}
	return Verify(key, delegation.UnsignedBody(), delegation.Signature.Value)
}
