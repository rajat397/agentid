package agentid

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	StatusValid     = 0x00
	StatusRevoked   = 0x01
	StatusSuspended = 0x02
)

// EncodeStatusList packs statuses LSB-first into a ZLIB compressed byte array.
func EncodeStatusList(statuses []int, bits int) (map[string]any, error) {
	switch bits {
	case 1, 2, 4, 8:
	default:
		return nil, errors.New("bits must be 1, 2, 4 or 8")
	}
	perByte := 8 / bits
	raw := make([]byte, (len(statuses)+perByte-1)/perByte)
	for i, status := range statuses {
		if status < 0 || status >= (1<<bits) {
			return nil, fmt.Errorf("status %d does not fit in %d bits", status, bits)
		}
		raw[i/perByte] |= byte(status) << uint((i%perByte)*bits)
	}
	var buf bytes.Buffer
	writer, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(raw); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return map[string]any{
		"bits": bits,
		"lst":  base64.RawURLEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// DecodeStatusList expands a status list into its individual values.
func DecodeStatusList(statusList map[string]any, count int) ([]int, error) {
	bits := intValue(statusList["bits"])
	compressed, err := base64.RawURLEncoding.DecodeString(stringField(statusList, "lst"))
	if err != nil {
		return nil, err
	}
	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	perByte := 8 / bits
	mask := byte((1 << bits) - 1)
	out := make([]int, 0, count)
	for i := 0; i < count; i++ {
		var value byte
		if i/perByte < len(raw) {
			value = raw[i/perByte] >> uint((i%perByte)*bits)
		}
		out = append(out, int(value&mask))
	}
	return out, nil
}

// BuildStatusToken returns a compact signed statuslist+jwt.
func BuildStatusToken(uri string, statuses []int, signer Signer,
	iat, exp, ttl int) (string, error) {
	encoded, err := EncodeStatusList(statuses, 2)
	if err != nil {
		return "", err
	}
	header := map[string]any{"alg": "ES256", "typ": "statuslist+jwt", "kid": signer.Kid()}
	payload := map[string]any{
		"sub": uri, "iat": iat, "exp": exp, "ttl": ttl,
		"status_list": encoded, "status_count": len(statuses),
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON)
	signature, err := signer.SignRaw([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + signature, nil
}

// VerifyStatusToken checks signature, header and freshness; returns the payload.
func VerifyStatusToken(token string, publicKeys map[string]string,
	now, maxStatusAge int) (map[string]any, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, errors.New("malformed statuslist+jwt")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("malformed statuslist+jwt")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed statuslist+jwt")
	}
	var header, payload map[string]any
	decoder := json.NewDecoder(bytes.NewReader(headerJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&header); err != nil {
		return nil, errors.New("malformed statuslist+jwt")
	}
	decoder = json.NewDecoder(bytes.NewReader(payloadJSON))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, errors.New("malformed statuslist+jwt")
	}
	if stringField(header, "typ") != "statuslist+jwt" || stringField(header, "alg") != "ES256" {
		return nil, errors.New("unsupported statuslist+jwt header")
	}
	pem, ok := publicKeys[stringField(header, "kid")]
	if !ok {
		return nil, errors.New("unknown status signing key")
	}
	key, err := ParsePublicPEM([]byte(pem))
	if err != nil || !VerifyRaw(key, []byte(parts[0]+"."+parts[1]), parts[2]) {
		return nil, errors.New("invalid statuslist+jwt signature")
	}
	issued := intValue(payload["iat"])
	ttl := intValue(payload["ttl"])
	if ttl == 0 {
		ttl = maxStatusAge
	}
	if ttl > maxStatusAge {
		ttl = maxStatusAge
	}
	if now < issued || now-issued > ttl {
		return nil, errors.New("stale statuslist+jwt")
	}
	if expiry := intValue(payload["exp"]); expiry != 0 && now > expiry {
		return nil, errors.New("stale statuslist+jwt (expired)")
	}
	if AsMap(payload["status_list"]) == nil || payload["status_count"] == nil {
		return nil, errors.New("malformed statuslist+jwt (missing status fields)")
	}
	return payload, nil
}

// CheckStatus resolves one index, failing closed on malformed or stale input.
func CheckStatus(token string, idx int, publicKeys map[string]string,
	maxStatusAge, now int) (int, error) {
	payload, err := VerifyStatusToken(token, publicKeys, now, maxStatusAge)
	if err != nil {
		return 0, err
	}
	count := intValue(payload["status_count"])
	if idx < 0 || idx >= count {
		return 0, fmt.Errorf("status index %d out of range", idx)
	}
	statuses, err := DecodeStatusList(AsMap(payload["status_list"]), count)
	if err != nil {
		return 0, err
	}
	return statuses[idx], nil
}

func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	return append(parts, token[start:])
}

func statusTokenNow() int { return int(time.Now().Unix()) }

// VerifyStatusTokenAtIssuedTime verifies signature and freshness relative to
// the token's own iat — used for archived tokens and offline PEP caches.
func VerifyStatusTokenAtIssuedTime(token string, publicKeys map[string]string,
	maxStatusAge int) (map[string]any, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, errors.New("malformed statuslist+jwt")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	value, err := DecodeJSON(payloadJSON)
	if err != nil {
		return nil, err
	}
	return VerifyStatusToken(token, publicKeys, intValue(AsMap(value)["iat"]), maxStatusAge)
}
