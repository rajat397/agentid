package integration

import (
	"strings"
	"testing"
)

// Scenario: a numeric predicate cannot be satisfied by a string, and the
// failure must be a type error the auditor can re-derive. A Type Profile is
// the sanctioned escape hatch for application-specific attribute types.
func TestScenarioPredicateTypingAndTypeProfile(t *testing.T) {
	w := NewWorld(t)

	bad := w.TypedCall(map[string]any{"rows": "many"}, nil)
	if bad == nil {
		t.Fatal("typed evaluation stub still active")
	}
	errObject := bad["error"]
	if errObject == nil || !strings.Contains(spanSetJSON([]map[string]any{AsMapValue(errObject)}), "type") {
		t.Fatalf("non-numeric value was not rejected as a type error: %+v", bad)
	}

	profile := map[string]any{
		"attributes": map[string]any{
			"/attributes/priority": "enum",
		},
		"enum_values": map[string]any{
			"/attributes/priority": []any{"low", "high"},
		},
	}
	allowed := w.TypedCall(map[string]any{"priority": "high"}, profile)
	if allowed == nil || AsMapValue(allowed["error"]) != nil {
		t.Fatalf("typed enum value rejected: %+v", allowed)
	}
}
