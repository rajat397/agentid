package agentid

import "fmt"

// Sensitivity tiers are ordinal. The rank is derived, never trusted from the
// caller, so an `eq`/`max` predicate cannot be bypassed with a forged rank.
const (
	TierPublic       = "public"
	TierInternal     = "internal"
	TierConfidential = "confidential"
	TierRegulated    = "regulated"
)

var sensitivityRank = map[string]int{
	TierPublic: 0, TierInternal: 1, TierConfidential: 2, TierRegulated: 3,
}

// NormalizeSensitivity derives `sensitivity_rank` from `sensitivity_tier` when
// a tier is present. It rejects unknown tiers and never accepts a caller-
// supplied rank that disagrees with the tier.
func NormalizeSensitivity(action map[string]any) error {
	tier, ok := action["sensitivity_tier"]
	if !ok || tier == nil {
		return nil
	}
	name, ok := tier.(string)
	if !ok {
		return fmt.Errorf("sensitivity_tier must be a string")
	}
	rank, valid := sensitivityRank[name]
	if !valid {
		return fmt.Errorf("unknown sensitivity tier %q", name)
	}
	if supplied, exists := action["sensitivity_rank"]; exists {
		if fmt.Sprint(supplied) != fmt.Sprint(rank) {
			return fmt.Errorf("sensitivity_rank disagrees with tier %q", name)
		}
	}
	action["sensitivity_rank"] = fmt.Sprint(rank)
	return nil
}
