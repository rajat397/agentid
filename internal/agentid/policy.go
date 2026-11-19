package agentid

import (
	"errors"
)

// PolicySetDigest content-addresses the ordered set of profiles actually used
// for a decision. Receipts name this digest, not any single profile.
func PolicySetDigest(profiles []Profile) (string, error) {
	documents := []any{}
	for _, profile := range profiles {
		documents = append(documents, profile.Document())
	}
	data, err := CanonicalJSON(documents)
	if err != nil {
		return "", err
	}
	return DigestSHA256(data), nil
}

// EvaluatePolicySet evaluates every profile and combines the decisions using
// deny-overrides. Every profile must pin that algorithm.
func EvaluatePolicySet(chain []Delegation, action map[string]any, profiles []Profile,
	publicPEM []byte, opts ValidationOptions) (ValidationResult, error) {
	if len(profiles) == 0 {
		return ValidationResult{Outcome: "invalid",
			Reason: "implicit deny: no policy decision"}, nil
	}
	decisions := make([]Decision, 0, len(profiles))
	for _, profile := range profiles {
		if profile.Combining != CombiningDenyOverrides {
			return ValidationResult{}, errors.New(
				"unsupported combining algorithm: " + profile.Combining)
		}
		result := Validate(chain, action, profile, publicPEM, opts)
		decisions = append(decisions, Decision{
			Outcome: result.Outcome, Reason: result.Reason,
			Obligations: result.Obligations, Evaluated: result.ConstraintsEvaluated,
		})
	}
	combined := Combine(decisions)
	return ValidationResult{
		Outcome: combined.Outcome, Reason: combined.Reason,
		Obligations: combined.Obligations, ConstraintsEvaluated: combined.Evaluated,
	}, nil
}
