// Package agentid is the Go implementation of the universal agent identity
// reference: canonical envelopes, attribute-path constraints, signed chains,
// receipts, revocation status, and offline evidence verification.
package agentid

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"time"
	"unicode/utf16"
)

// CanonicalJSON implements the deterministic subset used by signed artifacts:
// sorted object keys, compact separators, no HTML escaping, ASCII-only
// strings, integers only (decimal strings are used for numeric attributes).
func CanonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, v)
	case json.Number:
		if _, err := strconv.ParseInt(v.String(), 10, 64); err != nil {
			return fmt.Errorf("floating point values are not allowed in signed artifacts: %s", v)
		}
		buf.WriteString(v.String())
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			buf.WriteString(strconv.FormatInt(rv.Int(), 10))
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
		case reflect.Float32, reflect.Float64:
			return errors.New("floating point values are not allowed in signed artifacts")
		case reflect.String:
			writeCanonicalString(buf, rv.String())
		case reflect.Bool:
			writeCanonicalBool(buf, rv.Bool())
		case reflect.Slice, reflect.Array:
			buf.WriteByte('[')
			for i := 0; i < rv.Len(); i++ {
				if i > 0 {
					buf.WriteByte(',')
				}
				if err := writeCanonical(buf, rv.Index(i).Interface()); err != nil {
					return err
				}
			}
			buf.WriteByte(']')
		case reflect.Map:
			keys := make([]string, 0, rv.Len())
			iter := rv.MapRange()
			for iter.Next() {
				key := iter.Key()
				if key.Kind() != reflect.String {
					return errors.New("canonical JSON map keys must be strings")
				}
				keys = append(keys, key.String())
			}
			sort.Strings(keys)
			buf.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					buf.WriteByte(',')
				}
				writeCanonicalString(buf, key)
				buf.WriteByte(':')
				if err := writeCanonical(buf, rv.MapIndex(reflect.ValueOf(key)).Interface()); err != nil {
					return err
				}
			}
			buf.WriteByte('}')
		case reflect.Struct:
			fields := make(map[string]any)
			rt := rv.Type()
			for i := 0; i < rt.NumField(); i++ {
				field := rt.Field(i)
				if field.PkgPath != "" {
					continue
				}
				name := field.Tag.Get("json")
				if name == "" {
					name = field.Name
				}
				if name == "-" {
					continue
				}
				fields[name] = rv.Field(i).Interface()
			}
			return writeCanonical(buf, fields)
		case reflect.Pointer, reflect.Interface:
			if rv.IsNil() {
				buf.WriteString("null")
				return nil
			}
			return writeCanonical(buf, rv.Elem().Interface())
		default:
			return fmt.Errorf("cannot canonicalize %T", value)
		}
	}
	return nil
}

func writeCanonicalBool(buf *bytes.Buffer, b bool) {
	if b {
		buf.WriteString("true")
	} else {
		buf.WriteString("false")
	}
}

func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 || r > 0x7e {
				for _, unit := range utf16.Encode([]rune{r}) {
					fmt.Fprintf(buf, `\u%04x`, unit)
				}
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// DigestSHA256 returns the lowercase hex SHA-256 of data.
func DigestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

// B64URLDigestSHA256 returns the unpadded base64url SHA-256 of data.
func B64URLDigestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func base64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeJSON decodes JSON with json.Number preserving integer tokens.
func DecodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// AsMap coerces a decoded JSON value to a string-keyed map.
func AsMap(value any) map[string]any {
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return nil
}

// AsSlice coerces a decoded JSON value to a slice.
func AsSlice(value any) []any {
	if s, ok := value.([]any); ok {
		return s
	}
	return nil
}

func dateTimeNow() time.Time { return time.Now().UTC() }
