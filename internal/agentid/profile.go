package agentid

import (
	"errors"
)

// Profile is the content-addressed validation contract from the IETF mandate draft.
type Profile struct {
	URI                      string
	Iss                      string
	MaxClockSkew             int
	MaxPopWindow             int
	MaxTokenLifetime         int
	MaxStatusAge             int
	MaxChainLength           int
	Predicates               []string
	StatusValues             map[string]any
	SignatureAlgs            []string
	PQSign                   bool
	RequireTrustedProvenance bool
	RequireSignedApprovals   bool
	StageAllowlist           []string
	Combining                string
	TypeProfile              map[string]any
}

func (p Profile) document() map[string]any {
	return map[string]any{
		"iss":                        p.Iss,
		"max_chain_length":           p.MaxChainLength,
		"max_clock_skew":             p.MaxClockSkew,
		"max_pop_window":             p.MaxPopWindow,
		"max_status_age":             p.MaxStatusAge,
		"max_token_lifetime":         p.MaxTokenLifetime,
		"predicates":                 p.Predicates,
		"status_values":              p.StatusValues,
		"signature_algs":             p.SignatureAlgs,
		"pq_sign":                    p.PQSign,
		"require_trusted_provenance": p.RequireTrustedProvenance,
		"require_signed_approvals":   p.RequireSignedApprovals,
		"stage_allowlist":            p.StageAllowlist,
		"combining":                  p.Combining,
		"type_profile":               p.TypeProfile,
	}
}

// Document returns the content-addressed profile document.
func (p Profile) Document() map[string]any { return p.document() }

// Digest is the base64url SHA-256 of the canonical profile document.
func (p Profile) Digest() (string, error) {
	data, err := CanonicalJSON(p.document())
	if err != nil {
		return "", err
	}
	return B64URLDigestSHA256(data), nil
}

// ProfileFromMap loads and validates a profile document.
func ProfileFromMap(raw map[string]any) (Profile, error) {
	required := []string{"iss", "max_clock_skew", "max_pop_window",
		"max_token_lifetime", "max_status_age", "max_chain_length", "predicates"}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			return Profile{}, errors.New("profile missing required key: " + key)
		}
	}
	predicates := stringList(raw["predicates"])
	if len(predicates) == 0 {
		return Profile{}, errors.New("profile.predicates must be a non-empty list")
	}
	algs := stringList(raw["signature_algs"])
	if len(algs) == 0 {
		algs = []string{"ES256"}
	}
	status := map[string]any{}
	if rawStatus, ok := raw["status_values"].(map[string]any); ok {
		status = rawStatus
	}
	typeProfile := AsMap(raw["type_profile"])
	stageAllowlist := stringList(raw["stage_allowlist"])
	combining := stringField(raw, "combining")
	if combining == "" {
		combining = CombiningDenyOverrides
	}
	requireSignedApprovals := false
	if value, ok := raw["require_signed_approvals"]; ok {
		if flag, ok := value.(bool); ok {
			requireSignedApprovals = flag
		}
	}
	requireTrusted := false
	if value, ok := raw["require_trusted_provenance"]; ok {
		if flag, ok := value.(bool); ok {
			requireTrusted = flag
		}
	}
	pqSign := true
	if value, ok := raw["pq_sign"]; ok {
		if flag, ok := value.(bool); ok {
			pqSign = flag
		}
	}
	return Profile{
		URI:                      stringField(raw, "uri"),
		Iss:                      stringField(raw, "iss"),
		MaxClockSkew:             intValue(raw["max_clock_skew"]),
		MaxPopWindow:             intValue(raw["max_pop_window"]),
		MaxTokenLifetime:         intValue(raw["max_token_lifetime"]),
		MaxStatusAge:             intValue(raw["max_status_age"]),
		MaxChainLength:           intValue(raw["max_chain_length"]),
		Predicates:               predicates,
		StatusValues:             status,
		SignatureAlgs:            algs,
		PQSign:                   pqSign,
		RequireTrustedProvenance: requireTrusted,
		RequireSignedApprovals:   requireSignedApprovals,
		StageAllowlist:           stageAllowlist,
		Combining:                combining,
		TypeProfile:              typeProfile,
	}, nil
}

// ExampleProfile mirrors spec/validation-profile.example.json.
func ExampleProfile() Profile {
	return Profile{
		URI:                    "https://example.invalid/profiles/agentic-v1.json",
		Iss:                    "example-rp",
		MaxClockSkew:           30,
		MaxPopWindow:           300,
		MaxTokenLifetime:       900,
		MaxStatusAge:           60,
		MaxChainLength:         3,
		Predicates:             []string{"eq", "in", "max", "min", "window", "sum_max", "cosign_above"},
		StatusValues:           map[string]any{"0x02": "suspended"},
		SignatureAlgs:          []string{"ES256"},
		PQSign:                 true,
		RequireSignedApprovals: true,
		Combining:              CombiningDenyOverrides,
	}
}

// AllowsPredicate reports whether the profile admits a predicate type.
func (p Profile) AllowsPredicate(kind string) bool {
	for _, candidate := range p.Predicates {
		if candidate == kind {
			return true
		}
	}
	return false
}

// AllowsAlgorithm reports whether the profile admits a signature algorithm.
func (p Profile) AllowsAlgorithm(alg string) bool {
	for _, candidate := range p.SignatureAlgs {
		if candidate == alg {
			return true
		}
	}
	return false
}

// AllowsPQ reports whether this fleet signs with ML-DSA in addition to ES256.
func (p Profile) AllowsPQ() bool { return p.PQSign }

func stringList(value any) []string {
	switch items := value.(type) {
	case []string:
		if items == nil {
			return nil
		}
		return append([]string{}, items...)
	case []any:
		if items == nil {
			return nil
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, stringValue(item))
		}
		return out
	}
	return nil
}
