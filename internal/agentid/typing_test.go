package agentid

import (
	"strings"
	"testing"
)

func TestTypeProfileRejectsWrongDeclaredType(t *testing.T) {
	profile, err := TypeProfileFromMap(map[string]any{
		"attributes": map[string]any{"/attributes/count": "enum"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Validate("/attributes/count", "5", "max"); err == nil ||
		!strings.Contains(err.Error(), "type error") {
		t.Fatalf("declared enum did not reject numeric predicate: %v", err)
	}
}

func TestTypeProfileEnumValues(t *testing.T) {
	profile, err := TypeProfileFromMap(map[string]any{
		"attributes":  map[string]any{"/attributes/priority": "enum"},
		"enum_values": map[string]any{"/attributes/priority": []any{"low", "high"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Validate("/attributes/priority", "high", "in"); err != nil {
		t.Fatalf("declared enum value rejected: %v", err)
	}
	if err := profile.Validate("/attributes/priority", "urgent", "in"); err == nil {
		t.Fatal("undeclared enum value accepted")
	}
}

func TestTypeProfileRejectsMalformedDeclaration(t *testing.T) {
	if _, err := TypeProfileFromMap(map[string]any{
		"attributes": map[string]any{"/attributes/x": 5},
	}); err == nil {
		t.Fatal("non-string type declaration accepted")
	}
}

func TestImplicitTypeRules(t *testing.T) {
	if err := (*TypeProfile)(nil).Validate("/attributes/rows", "many", "max"); err == nil {
		t.Fatal("non-numeric value accepted by numeric predicate")
	}
	if err := (*TypeProfile)(nil).Validate("/time", "not-a-time", "window"); err == nil {
		t.Fatal("non-timestamp accepted by window predicate")
	}
}
