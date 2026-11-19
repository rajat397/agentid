package agentid

import (
	"bytes"
	"sort"
)

// CombiningDenyOverrides is the only algorithm pinned in V1: a deny from any
// policy dominates every permit; indeterminate dominates absence of a permit;
// no permit at all is an implicit deny.
const CombiningDenyOverrides = "deny-overrides"

// Decision is one profile's evaluation result, including its obligations.
type Decision struct {
	Outcome     string
	Reason      string
	Obligations []any
	Evaluated   []any
}

// Combine applies deny-overrides to a set of decisions. Obligations are
// unioned canonically so artifact digests do not depend on profile order.
func Combine(decisions []Decision) Decision {
	if len(decisions) == 0 {
		return Decision{Outcome: "invalid", Reason: "implicit deny: no policy decision"}
	}
	var firstInvalid, firstIndeterminate, firstValid *Decision
	for i := range decisions {
		decision := &decisions[i]
		switch decision.Outcome {
		case "invalid":
			if firstInvalid == nil {
				firstInvalid = decision
			}
		case "indeterminate":
			if firstIndeterminate == nil {
				firstIndeterminate = decision
			}
		case "valid":
			if firstValid == nil {
				firstValid = decision
			}
		default:
			if firstInvalid == nil {
				firstInvalid = decision
			}
		}
	}
	winner := firstValid
	reason := "within constraints"
	if firstInvalid != nil {
		winner, reason = firstInvalid, firstInvalid.Reason
	} else if firstIndeterminate != nil {
		winner, reason = firstIndeterminate, firstIndeterminate.Reason
	} else if firstValid == nil {
		return Decision{Outcome: "invalid", Reason: "implicit deny: no policy permits",
			Obligations: CanonicalObligations(nil), Evaluated: []any{}}
	}
	return Decision{
		Outcome: winner.Outcome, Reason: reason,
		Obligations: CanonicalObligations(allObligations(decisions)),
		Evaluated:   winner.Evaluated,
	}
}

func allObligations(decisions []Decision) []any {
	all := []any{}
	for _, decision := range decisions {
		all = append(all, decision.Obligations...)
	}
	return all
}

// CanonicalObligations sorts and de-duplicates obligations by their canonical
// JSON bytes. Ordering is therefore a property of the content, not input order.
func CanonicalObligations(obligations []any) []any {
	type item struct {
		data  []byte
		value any
	}
	items := make([]item, 0, len(obligations))
	seen := map[string]bool{}
	for _, obligation := range obligations {
		data, err := CanonicalJSON(obligation)
		if err != nil {
			continue
		}
		key := string(data)
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, item{data: data, value: obligation})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].data, items[j].data) < 0
	})
	out := make([]any, 0, len(items))
	for _, entry := range items {
		out = append(out, entry.value)
	}
	return out
}
