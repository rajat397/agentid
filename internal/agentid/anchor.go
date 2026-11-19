package agentid

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	oidSHA256  = "2.16.840.1.101.3.4.2.1"
	oidTSTInfo = "1.2.840.113549.1.9.16.1.4"
	DefaultTSA = "https://freetsa.org/tsr"
)

func derLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	raw := []byte{}
	for n > 0 {
		raw = append([]byte{byte(n & 0xff)}, raw...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(raw))}, raw...)
}

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLength(len(content))...)
	return append(out, content...)
}

func derSequence(content []byte) []byte { return tlv(0x30, content) }
func derNull() []byte                   { return tlv(0x05, nil) }
func derOctetString(data []byte) []byte { return tlv(0x04, data) }
func derInteger(n int64) []byte {
	raw := []byte{}
	for n > 0 {
		raw = append([]byte{byte(n & 0xff)}, raw...)
		n >>= 8
	}
	if len(raw) == 0 {
		raw = []byte{0}
	}
	if raw[0]&0x80 != 0 {
		raw = append([]byte{0}, raw...)
	}
	return tlv(0x02, raw)
}

func derOID(dotted string) []byte {
	parts := strings.Split(dotted, ".")
	values := make([]int, 0, len(parts))
	for _, part := range parts {
		var value int
		fmt.Sscanf(part, "%d", &value)
		values = append(values, value)
	}
	content := []byte{byte(values[0]*40 + values[1])}
	for _, value := range values[2:] {
		chunk := []byte{byte(value & 0x7f)}
		value >>= 7
		for value > 0 {
			chunk = append([]byte{byte(value&0x7f) | 0x80}, chunk...)
			value >>= 7
		}
		content = append(content, chunk...)
	}
	return tlv(0x06, content)
}

type derReader struct{ data []byte }

func (r *derReader) read() (byte, []byte, error) {
	if len(r.data) < 2 {
		return 0, nil, errors.New("truncated DER")
	}
	tag := r.data[0]
	length := int(r.data[1])
	header := 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(r.data) < 2+count {
			return 0, nil, errors.New("invalid DER length")
		}
		length = 0
		for _, b := range r.data[2 : 2+count] {
			length = (length << 8) | int(b)
		}
		header = 2 + count
	}
	if len(r.data) < header+length {
		return 0, nil, errors.New("truncated DER value")
	}
	content := r.data[header : header+length]
	r.data = r.data[header+length:]
	return tag, content, nil
}

type derItem struct {
	tag     byte
	content []byte
}

func walkDER(data []byte) []derItem {
	reader := derReader{data: data}
	items := []derItem{}
	for {
		tag, content, err := reader.read()
		if err != nil {
			return items
		}
		items = append(items, derItem{tag, content})
		if tag&0x20 != 0 {
			items = append(items, walkDER(content)...)
		}
	}
}

func decodeOID(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	parts := []int{int(content[0]) / 40, int(content[0]) % 40}
	value := int64(0)
	for _, b := range content[1:] {
		value = (value << 7) | int64(b&0x7f)
		if b&0x80 == 0 {
			parts = append(parts, int(value))
			value = 0
		}
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, fmt.Sprint(part))
	}
	return strings.Join(out, ".")
}

// ChainHead returns the hash every earlier receipt commits to.
func ChainHead(ledger *Ledger) (string, error) {
	if len(ledger.Receipts) == 0 {
		return "", errors.New("cannot anchor an empty ledger")
	}
	if problems := ledger.VerifyHashes(); len(problems) > 0 {
		return "", errors.New("ledger does not verify: " + problems[0])
	}
	hash, err := ledger.Receipts[len(ledger.Receipts)-1].Hash()
	if err != nil {
		return "", err
	}
	return hash, nil
}

// BuildTimestampReq builds a minimal RFC 3161 TimeStampReq.
func BuildTimestampReq(hashHex string) ([]byte, error) {
	digest, err := hex.DecodeString(hashHex)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("chain head must be a SHA-256 hex digest")
	}
	alg := derSequence(append(derOID(oidSHA256), derNull()...))
	imprint := derSequence(append(alg, derOctetString(digest)...))
	content := derInteger(1)
	content = append(content, imprint...)
	content = append(content, 0x01, 0x01, 0xff)
	return derSequence(content), nil
}

// TimestampInfo is the binding extracted from a TimeStampResp.
type TimestampInfo struct {
	Status         int
	MessageImprint string
	GenTime        string
	Serial         int64
}

// ParseTimestampResp structurally parses a granted RFC 3161 response.
func ParseTimestampResp(der []byte) (TimestampInfo, error) {
	top := derReader{data: der}
	tag, content, err := top.read()
	if err != nil || tag != 0x30 {
		return TimestampInfo{}, errors.New("TimeStampResp must be a SEQUENCE")
	}
	statusReader := derReader{data: content}
	statusTag, statusContent, err := statusReader.read()
	if err != nil || statusTag != 0x30 {
		return TimestampInfo{}, errors.New("expected PKIStatusInfo")
	}
	inner := derReader{data: statusContent}
	intTag, intContent, err := inner.read()
	if err != nil || intTag != 0x02 {
		return TimestampInfo{}, errors.New("expected PKIStatus INTEGER")
	}
	status := intFromBytes(intContent)
	if status != 0 && status != 1 {
		return TimestampInfo{}, fmt.Errorf("TSA refused the request (PKIStatus=%d)", status)
	}

	flat := walkDER(der)
	tstIndex := -1
	for i, item := range flat {
		if item.tag == 0x06 && decodeOID(item.content) == oidTSTInfo {
			tstIndex = i
			break
		}
	}
	if tstIndex < 0 {
		return TimestampInfo{}, errors.New("no TSTInfo content type in response")
	}
	var tstInfo []byte
	for _, item := range flat[tstIndex+1:] {
		if item.tag == 0x04 {
			tstInfo = item.content
			break
		}
	}
	if tstInfo == nil {
		return TimestampInfo{}, errors.New("TSTInfo octet string not found")
	}
	infoReader := derReader{data: tstInfo}
	infoTag, infoContent, err := infoReader.read()
	if err != nil || infoTag != 0x30 {
		return TimestampInfo{}, errors.New("TSTInfo must be a SEQUENCE")
	}
	fields := derReader{data: infoContent}
	if _, _, err := fields.read(); err != nil { // version
		return TimestampInfo{}, err
	}
	if _, _, err := fields.read(); err != nil { // policy OID
		return TimestampInfo{}, err
	}
	imprintTag, imprintContent, err := fields.read()
	if err != nil || imprintTag != 0x30 {
		return TimestampInfo{}, errors.New("expected messageImprint")
	}
	imprint := derReader{data: imprintContent}
	if _, _, err := imprint.read(); err != nil { // hashAlgorithm
		return TimestampInfo{}, err
	}
	hashTag, hashContent, err := imprint.read()
	if err != nil || hashTag != 0x04 {
		return TimestampInfo{}, errors.New("expected hashedMessage")
	}
	_, serialContent, err := fields.read()
	if err != nil {
		return TimestampInfo{}, err
	}
	timeTag, timeContent, err := fields.read()
	if err != nil || timeTag != 0x18 {
		return TimestampInfo{}, errors.New("expected genTime")
	}
	return TimestampInfo{
		Status: int(status), MessageImprint: hex.EncodeToString(hashContent),
		GenTime: string(timeContent), Serial: intFromBytes(serialContent),
	}, nil
}

// AnchorRecord is the verbatim, offline-verifiable timestamp artifact.
type AnchorRecord map[string]any

// VerifyAnchor checks that the anchor binds this exact ledger head.
func VerifyAnchor(record map[string]any, ledger *Ledger) []string {
	problems := []string{}
	head, err := ChainHead(ledger)
	if err != nil {
		return []string{err.Error()}
	}
	recordHead := stringField(record, "head_hash")
	if recordHead != head {
		problems = append(problems, fmt.Sprintf(
			"anchor binds %s… but chain head is %s…", shortHash(recordHead), shortHash(head)))
	}
	response, err := base64.StdEncoding.DecodeString(stringField(record, "response_der_b64"))
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	info, err := ParseTimestampResp(response)
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	if info.MessageImprint != recordHead {
		problems = append(problems, "TSTInfo inside the anchor names a different digest")
	}
	storedRequest, err := base64.StdEncoding.DecodeString(stringField(record, "request_der_b64"))
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	expected, err := BuildTimestampReq(recordHead)
	if err != nil || !bytes.Equal(storedRequest, expected) {
		problems = append(problems, "stored request does not match the recorded head hash")
	}
	return problems
}

// PostTimestamp posts a TimeStampReq, dialing IPv4 explicitly to avoid
// blackholed IPv6 routes in sandboxed environments.
func PostTimestamp(tsaURL string, request []byte, timeout time.Duration) ([]byte, error) {
	parsed, err := url.Parse(tsaURL)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(host, port))
		},
	}}
	response, err := client.Post(tsaURL, "application/timestamp-query", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("TSA returned HTTP %d", response.StatusCode)
	}
	return io.ReadAll(response.Body)
}

// LoadAnchors reads a JSONL anchor file, skipping blank lines.
func LoadAnchors(path string) ([]map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	anchors := []map[string]any{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		decoder := json.NewDecoder(strings.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&record); err != nil {
			return nil, err
		}
		anchors = append(anchors, record)
	}
	return anchors, nil
}

func shortHash(hash string) string {
	if len(hash) < 12 {
		return hash
	}
	return hash[:12]
}

func intFromBytes(data []byte) int64 {
	var value int64
	for _, b := range data {
		value = (value << 8) | int64(b)
	}
	return value
}

// AnchorLedger asks a TSA to stamp the current chain head and returns the
// verbatim response record for offline verification.
func AnchorLedger(ledger *Ledger, tsaURL string, timeout time.Duration) (map[string]any, error) {
	head, err := ChainHead(ledger)
	if err != nil {
		return nil, err
	}
	request, err := BuildTimestampReq(head)
	if err != nil {
		return nil, err
	}
	response, err := PostTimestamp(tsaURL, request, timeout)
	if err != nil {
		return nil, err
	}
	info, err := ParseTimestampResp(response)
	if err != nil {
		return nil, err
	}
	if info.MessageImprint != head {
		return nil, errors.New("TSA response binds a different digest — refusing to anchor")
	}
	return map[string]any{
		"head_hash": head, "head_seq": len(ledger.Receipts) - 1,
		"tsa_url":          tsaURL,
		"request_der_b64":  base64.StdEncoding.EncodeToString(request),
		"response_der_b64": base64.StdEncoding.EncodeToString(response),
		"gen_time":         info.GenTime, "serial": info.Serial,
		"anchored_at": dateTimeNow().Format(timeLayout),
	}, nil
}

// BuildMockTimestampResponse crafts a structurally valid TimeStampResp for a
// given head digest. It is a test/demo utility: CMS chain-of-trust verification
// against the TSA certificate is still an external openssl operation.
func BuildMockTimestampResponse(headHash, genTime string, serial int64) ([]byte, error) {
	digest, err := hex.DecodeString(headHash)
	if err != nil || len(digest) != 32 {
		return nil, errors.New("head must be a SHA-256 hex digest")
	}
	tstInfo := derSequence(concatBytes(
		derInteger(1),
		derOID("1.3.6.1.4.1.99999.1"),
		derSequence(concatBytes(
			derSequence(concatBytes(derOID(oidSHA256), derNull())),
			derOctetString(digest),
		)),
		derInteger(serial),
		tlv(0x18, []byte(genTime)),
	))
	status := derSequence(derInteger(0))
	content := derSequence(concatBytes(derOID(oidTSTInfo), derOctetString(tstInfo)))
	return derSequence(concatBytes(status, content)), nil
}

func concatBytes(parts ...[]byte) []byte {
	out := []byte{}
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
