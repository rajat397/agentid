package agentid

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixturePaths(t *testing.T) (string, string) {
	t.Helper()
	dir := filepath.Join("..", "..", "tests", "fixtures")
	return filepath.Join(dir, "demo-anchor.jsonl"), filepath.Join(dir, "demo-anchor.jsonl.ledger.jsonl")
}

func fixtureLedger(t *testing.T) *Ledger {
	t.Helper()
	_, ledgerPath := fixturePaths(t)
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	ledger := &Ledger{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		value, err := DecodeJSON([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		receipt := ReceiptFromMap(AsMap(value))
		if err := ledger.Append(&receipt); err != nil {
			t.Fatal(err)
		}
	}
	return ledger
}

func fixtureAnchor(t *testing.T) map[string]any {
	t.Helper()
	anchorPath, _ := fixturePaths(t)
	anchors, err := LoadAnchors(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	return anchors[0]
}

func TestAnchorFixturesVerifyOffline(t *testing.T) {
	ledger := fixtureLedger(t)
	anchor := fixtureAnchor(t)
	head, err := ChainHead(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if head != stringField(anchor, "head_hash") {
		t.Fatalf("head mismatch: %s vs %s", head, stringField(anchor, "head_hash"))
	}
	if problems := VerifyAnchor(anchor, ledger); len(problems) > 0 {
		t.Fatalf("fixture anchor failed: %v", problems)
	}
	response, err := base64.StdEncoding.DecodeString(stringField(anchor, "response_der_b64"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseTimestampResp(response)
	if err != nil {
		t.Fatal(err)
	}
	if info.MessageImprint != head || info.GenTime != stringField(anchor, "gen_time") {
		t.Fatalf("binding mismatch: %+v", info)
	}
}

func TestAnchorRejectsTampering(t *testing.T) {
	ledger := fixtureLedger(t)
	base := fixtureAnchor(t)

	headMismatch := map[string]any{}
	for key, value := range base {
		headMismatch[key] = value
	}
	headMismatch["head_hash"] = strings.Repeat("0", 64)
	if problems := VerifyAnchor(headMismatch, ledger); len(problems) == 0 {
		t.Fatal("head mismatch accepted")
	}

	imprintTampered := map[string]any{}
	for key, value := range base {
		imprintTampered[key] = value
	}
	der, err := base64.StdEncoding.DecodeString(stringField(base, "response_der_b64"))
	if err != nil {
		t.Fatal(err)
	}
	imprint := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var hi, lo byte
		hash := stringField(base, "head_hash")
		hi = hexNibble(hash[i*2])
		lo = hexNibble(hash[i*2+1])
		imprint[i] = hi<<4 | lo
	}
	at := bytesIndex(der, imprint)
	if at < 0 {
		t.Fatal("fixture imprint not found verbatim")
	}
	der[at] ^= 0x01
	imprintTampered["response_der_b64"] = base64.StdEncoding.EncodeToString(der)
	if problems := VerifyAnchor(imprintTampered, ledger); len(problems) == 0 {
		t.Fatal("imprint tamper accepted")
	}

	requestMismatch := map[string]any{}
	for key, value := range base {
		requestMismatch[key] = value
	}
	wrongRequest, err := BuildTimestampReq(strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	requestMismatch["request_der_b64"] = base64.StdEncoding.EncodeToString(wrongRequest)
	if problems := VerifyAnchor(requestMismatch, ledger); len(problems) == 0 {
		t.Fatal("request mismatch accepted")
	}

	tamperedLedger := fixtureLedger(t)
	tamperedLedger.Receipts[0].Action = "social.post.publish"
	if problems := VerifyAnchor(base, tamperedLedger); len(problems) == 0 {
		t.Fatal("ledger tamper accepted")
	}
}

func TestChainHeadRejectsEmptyLedger(t *testing.T) {
	if _, err := ChainHead(&Ledger{}); err == nil {
		t.Fatal("empty ledger was anchored")
	}
}

func TestBuildTimestampReqCarriesImprint(t *testing.T) {
	anchor := fixtureAnchor(t)
	head := stringField(anchor, "head_hash")
	der, err := BuildTimestampReq(head)
	if err != nil {
		t.Fatal(err)
	}
	imprint := make([]byte, 32)
	for i := 0; i < 32; i++ {
		imprint[i] = hexNibble(head[i*2])<<4 | hexNibble(head[i*2+1])
	}
	if bytesIndex(der, imprint) < 0 {
		t.Fatal("imprint missing from request DER")
	}
}

func hexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func TestRFC3161ManagerAndPostTimestamp(t *testing.T) {
	ledger := retentionLedger(t)
	head, err := ChainHead(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := BuildMockTimestampResponse(head, "20261120000000Z", 42)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(response)
	}))
	defer server.Close()

	manager, err := NewAnchorManager(AnchorConfig{TSAURL: server.URL,
		Cadence: AnchorCadence{MaxReceipts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := manager.Observe(ledger, "")
	if err != nil || len(anchors) != 1 {
		t.Fatalf("RFC 3161 anchoring failed: %d %v", len(anchors), err)
	}
	if problems := VerifyAnchorBinding(anchors[0]); len(problems) > 0 {
		t.Fatalf("anchor binding failed: %v", problems)
	}
	if len(manager.Pending()) != 0 {
		t.Fatal("anchor unexpectedly pending")
	}
	request, err := BuildTimestampReq(head)
	if err != nil {
		t.Fatal(err)
	}
	response, err := PostTimestamp(server.URL, request, time.Second)
	if err != nil {
		t.Fatalf("PostTimestamp failed: %v", err)
	}
	if _, err := ParseTimestampResp(response); err != nil {
		t.Fatalf("posted response invalid: %v", err)
	}
}
