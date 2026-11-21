package agentid

import (
	"fmt"
	"time"
)

// AttributeType is the declared type of an action-envelope attribute.
type AttributeType string

const (
	AttrDecimal AttributeType = "decimal"
	AttrString  AttributeType = "string"
	AttrEnum    AttributeType = "enum"
	AttrTime    AttributeType = "time"
	AttrBoolean AttributeType = "boolean"
)

// TypeProfile declares application-specific attribute types. It is the
// sanctioned escape hatch for custom values; predicates stay fixed at seven.
type TypeProfile struct {
	ID         string
	Attributes map[string]AttributeType
	EnumValues map[string][]string
}

// TypeProfileFromMap parses a type profile from a Validation Profile.
func TypeProfileFromMap(raw map[string]any) (*TypeProfile, error) {
	if raw == nil {
		return nil, nil
	}
	profile := &TypeProfile{
		ID:         stringField(raw, "id"),
		Attributes: map[string]AttributeType{},
		EnumValues: map[string][]string{},
	}
	for path, value := range AsMap(raw["attributes"]) {
		name, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("type profile attribute %s is not a string", path)
		}
		profile.Attributes[path] = AttributeType(name)
	}
	for path, values := range AsMap(raw["enum_values"]) {
		profile.EnumValues[path] = stringList(values)
	}
	return profile, nil
}

func expectedType(atomType string) AttributeType {
	switch atomType {
	case "max", "min", "sum_max", "cosign_above":
		return AttrDecimal
	case "window":
		return AttrTime
	default:
		return AttrString
	}
}

// Validate checks that an observed value is type-compatible with a predicate.
func (p *TypeProfile) Validate(path string, observed any, atomType string) error {
	expected := expectedType(atomType)
	if p != nil {
		if declared, ok := p.Attributes[path]; ok {
			if declared == AttrEnum && expected == AttrString {
				if values, exists := p.EnumValues[path]; exists {
					value := fmt.Sprint(observed)
					for _, candidate := range values {
						if candidate == value {
							return nil
						}
					}
					return fmt.Errorf("type error: %s value %q not in declared enum", path, value)
				}
			}
			if declared != expected {
				return fmt.Errorf("type error: %s declared %s but predicate expects %s",
					path, declared, expected)
			}
		}
	}
	switch expected {
	case AttrDecimal:
		if _, err := toDecimal(observed); err != nil {
			return fmt.Errorf("type error: %s expects decimal, observed %T", path, observed)
		}
	case AttrTime:
		text := fmt.Sprint(observed)
		if _, err := time.Parse(timeLayout, text); err != nil {
			return fmt.Errorf("type error: %s expects timestamp, observed %q", path, text)
		}
	case AttrString:
		if _, ok := observed.(string); !ok {
			return fmt.Errorf("type error: %s expects string, observed %T", path, observed)
		}
	}
	return nil
}
