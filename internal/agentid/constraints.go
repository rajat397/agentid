package agentid

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

var predicateTypes = map[string]bool{
	"eq": true, "in": true, "max": true, "min": true,
	"window": true, "sum_max": true, "cosign_above": true,
}

// Permission is an explicit (action, system) pair.
type Permission struct {
	Action string
	System string
}

// Atom is one predicate over an RFC 6901 pointer into the action envelope.
type Atom struct {
	Type          string
	Path          string
	Value         string
	Values        []any
	Max           string
	Key           string
	PeriodSeconds int
	Start         string
	End           string
	Legacy        string
}

// Normalize translates constraints into permissions and predicate atoms.
// Legacy money-first keys are accepted as sugar for previously issued grants.
func Normalize(constraints map[string]any) ([]Permission, []Atom, error) {
	if constraints == nil {
		return nil, nil, errors.New("constraints must be an object")
	}
	var permissions []Permission
	if raw, ok := constraints["permissions"].([]any); ok {
		for _, item := range raw {
			m := AsMap(item)
			if m == nil {
				return nil, nil, errors.New("permission must be an object")
			}
			permissions = append(permissions, Permission{
				Action: stringField(m, "action"), System: stringField(m, "system"),
			})
		}
	}

	var atoms []Atom
	if raw, ok := constraints["max_amount"].(map[string]any); ok {
		atoms = append(atoms, Atom{Type: "max", Path: "/attributes/amount",
			Value: stringValue(raw["value"]), Legacy: "max_amount"})
	}
	if raw, ok := constraints["requires_human_approval_above"].(map[string]any); ok {
		atoms = append(atoms, Atom{Type: "cosign_above", Path: "/attributes/amount",
			Value: stringValue(raw["value"]), Legacy: "requires_human_approval_above"})
	}
	if raw, ok := constraints["budget"].(map[string]any); ok {
		atom := Atom{Type: "sum_max", Path: "/attributes/amount",
			Key: stringValue(raw["key"]), Max: stringValue(raw["value"]), Legacy: "budget"}
		if atom.Key == "" {
			atom.Key = "budget"
		}
		if seconds, ok := raw["period_seconds"]; ok {
			atom.PeriodSeconds = intValue(seconds)
		}
		atoms = append(atoms, atom)
	}
	if raw, ok := constraints["predicates"].([]any); ok {
		for _, item := range raw {
			atom, err := parseAtom(AsMap(item))
			if err != nil {
				return nil, nil, err
			}
			atoms = append(atoms, atom)
		}
	}
	return permissions, atoms, nil
}

func parseAtom(raw map[string]any) (Atom, error) {
	if raw == nil {
		return Atom{}, errors.New("predicate must be an object")
	}
	kind := stringField(raw, "type")
	if !predicateTypes[kind] {
		return Atom{}, fmt.Errorf("unknown predicate type: %q", kind)
	}
	atom := Atom{Type: kind, Path: stringField(raw, "path")}
	pathDefaults := map[string]bool{"eq": true, "max": true, "min": true,
		"sum_max": true, "cosign_above": true}
	if pathDefaults[kind] && atom.Path == "" {
		atom.Path = "/attributes/amount"
	}
	if atom.Path != "" && !strings.HasPrefix(atom.Path, "/") {
		atom.Path = "/attributes/" + atom.Path
	}
	switch kind {
	case "in":
		values, ok := raw["values"].([]any)
		if atom.Path == "" || !ok || len(values) == 0 {
			return Atom{}, errors.New("in predicate needs a path and a non-empty values list")
		}
		atom.Values = values
	case "eq", "cosign_above":
		if _, ok := raw["value"]; !ok {
			return Atom{}, fmt.Errorf("%s predicate needs a value", kind)
		}
		atom.Value = stringValue(raw["value"])
		if _, err := toDecimal(atom.Value); err != nil && kind == "cosign_above" {
			return Atom{}, err
		}
	case "max", "min":
		if _, ok := raw["value"]; !ok {
			return Atom{}, fmt.Errorf("%s predicate needs a value", kind)
		}
		atom.Value = stringValue(raw["value"])
		if _, err := toDecimal(atom.Value); err != nil {
			return Atom{}, err
		}
	case "sum_max":
		if _, ok := raw["max"]; !ok {
			return Atom{}, errors.New("sum_max predicate needs a max")
		}
		atom.Max = stringValue(raw["max"])
		if _, err := toDecimal(atom.Max); err != nil {
			return Atom{}, err
		}
		atom.Key = stringValue(raw["key"])
		if atom.Key == "" {
			atom.Key = "budget"
		}
		if seconds, ok := raw["period_seconds"]; ok {
			atom.PeriodSeconds = intValue(seconds)
		}
	case "window":
		atom.Start = stringField(raw, "start")
		atom.End = stringField(raw, "end")
		if atom.Start == "" || atom.End == "" {
			return Atom{}, errors.New("window predicate needs start and end")
		}
		if atom.Path == "" {
			atom.Path = "/time"
		}
	}
	return atom, nil
}

// Resolve follows an RFC 6901 pointer; a bare name means /attributes/<name>.
func Resolve(document any, pointer string) (any, error) {
	if !strings.HasPrefix(pointer, "/") {
		pointer = "/attributes/" + pointer
	}
	current := document
	for _, raw := range strings.Split(pointer, "/")[1:] {
		token := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			found, ok := value[token]
			if !ok {
				return nil, fmt.Errorf("path %s not found", pointer)
			}
			current = found
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(value) {
				return nil, fmt.Errorf("path %s not found", pointer)
			}
			current = value[index]
		default:
			return nil, fmt.Errorf("path %s not found", pointer)
		}
	}
	return current, nil
}

// Evaluate returns (satisfied, observed, failure reason) for local predicates.
func Evaluate(atom Atom, view map[string]any) (bool, any, string) {
	observed, err := Resolve(view, atom.Path)
	if err != nil {
		return false, nil, "attribute " + atom.Path + " is missing"
	}
	switch atom.Type {
	case "eq":
		return fmt.Sprint(observed) == atom.Value, observed, ""
	case "in":
		for _, candidate := range atom.Values {
			if fmt.Sprint(candidate) == fmt.Sprint(observed) {
				return true, observed, ""
			}
		}
		return false, observed, ""
	case "max", "min":
		left, err1 := toDecimal(observed)
		right, err2 := toDecimal(atom.Value)
		if err1 != nil || err2 != nil {
			return false, observed, "non-numeric observation"
		}
		if atom.Type == "max" {
			return left.Cmp(right) <= 0, observed, ""
		}
		return left.Cmp(right) >= 0, observed, ""
	case "window":
		value := fmt.Sprint(observed)
		return atom.Start <= value && value <= atom.End, observed, ""
	default:
		// sum_max and cosign_above are resolved by the validator.
		return true, observed, ""
	}
}

func toDecimal(value any) (*big.Rat, error) {
	var text string
	switch v := value.(type) {
	case string:
		text = v
	case jsonNumber:
		text = v.String()
	case int:
		text = strconv.Itoa(v)
	case int64:
		text = strconv.FormatInt(v, 10)
	case float64:
		return nil, errors.New("floats are not allowed in signed artifacts")
	default:
		return nil, fmt.Errorf("not numeric: %T", value)
	}
	rat, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, fmt.Errorf("not numeric: %s", text)
	}
	return rat, nil
}

// AttenuationViolation returns a message if child widens parent, else "".
func AttenuationViolation(child, parent map[string]any) string {
	childPerms, childAtoms, err := Normalize(child)
	if err != nil {
		return "attenuation violated: malformed constraints"
	}
	parentPerms, parentAtoms, err := Normalize(parent)
	if err != nil {
		return "attenuation violated: malformed constraints"
	}
	parentSet := make(map[Permission]bool)
	for _, p := range parentPerms {
		parentSet[p] = true
	}
	for _, p := range childPerms {
		if !parentSet[p] {
			return "attenuation violated: child permissions exceed parent"
		}
	}
	parentAudience := stringField(parent, "aud")
	childAudience := stringField(child, "aud")
	if parentAudience != "" && childAudience != parentAudience {
		return "attenuation violated: child audience differs from parent"
	}
	parentStage := stringField(parent, "stage")
	childStage := stringField(child, "stage")
	if parentStage != "" && !StageWithin(parentStage, childStage) {
		return "attenuation violated: child stage exceeds parent stage ceiling"
	}
	for _, pa := range parentAtoms {
		found := false
		for _, ca := range childAtoms {
			if ca.Type == pa.Type && ca.Path == pa.Path && !looser(ca, pa) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("attenuation violated: child %s on %s is looser than parent",
				pa.Type, pa.Path)
		}
	}
	return ""
}

func looser(child, parent Atom) bool {
	switch parent.Type {
	case "eq":
		return child.Value != parent.Value
	case "in":
		set := make(map[string]bool)
		for _, value := range parent.Values {
			set[fmt.Sprint(value)] = true
		}
		for _, value := range child.Values {
			if !set[fmt.Sprint(value)] {
				return true
			}
		}
		return false
	case "max", "min", "sum_max", "cosign_above":
		leftBound := parent.Value
		if parent.Type == "sum_max" {
			leftBound = parent.Max
		}
		rightBound := child.Value
		if child.Type == "sum_max" {
			rightBound = child.Max
		}
		if parent.Type == "sum_max" && parent.Key != child.Key {
			return true
		}
		left, err1 := toDecimal(rightBound)
		right, err2 := toDecimal(leftBound)
		if err1 != nil || err2 != nil {
			return true
		}
		if parent.Type == "min" {
			return left.Cmp(right) < 0
		}
		return left.Cmp(right) > 0
	case "window":
		return child.Start < parent.Start || child.End > parent.End
	}
	return true
}

// Helpers for decoded JSON values.
type jsonNumber = interface {
	String() string
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if num, ok := value.(jsonNumber); ok {
		return num.String()
	}
	return fmt.Sprint(value)
}

func intValue(value any) int {
	switch v := value.(type) {
	case jsonNumber:
		n, _ := strconv.Atoi(v.String())
		return n
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
