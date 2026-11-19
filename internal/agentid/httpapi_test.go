package agentid

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerificationHandlers(t *testing.T) {
	demo, err := buildDemoLedger()
	if err != nil {
		t.Fatal(err)
	}
	handler := NewVerificationHandler(demo.ledger.SignerKeys)
	receiptJSON, err := CanonicalJSON(demo.ledger.Receipts[1].ToMap())
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/receipts/verify",
		bytes.NewReader(receiptJSON))
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("verify status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response verifyResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Verified || len(response.Checks) < 4 {
		t.Fatalf("valid receipt rejected: %+v", response)
	}
	foundAdditional := false
	for _, check := range response.Checks {
		if check.Name == "additional_signature_0" && check.OK {
			foundAdditional = true
		}
	}
	if !foundAdditional {
		t.Fatalf("PQ signature not checked: %+v", response.Checks)
	}

	keysRecorder := httptest.NewRecorder()
	handler.ServeHTTP(keysRecorder, httptest.NewRequest(http.MethodGet, "/v1/keys", nil))
	if keysRecorder.Code != http.StatusOK {
		t.Fatalf("keys status %d", keysRecorder.Code)
	}
	var keySet struct {
		Keys []KeyInfo `json:"keys"`
	}
	if err := json.Unmarshal(keysRecorder.Body.Bytes(), &keySet); err != nil {
		t.Fatal(err)
	}
	algs := map[string]bool{}
	for _, key := range keySet.Keys {
		algs[key.Alg] = true
	}
	if !algs["ES256"] || !algs[AlgMLDSA65] {
		t.Fatalf("key set missing algorithms: %v", algs)
	}

	tampered := ReceiptFromMap(AsMap(mustDecode(t, receiptJSON)))
	tampered.Signature.Value = "tampered"
	tamperedJSON, _ := CanonicalJSON(tampered.ToMap())
	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/receipts/verify",
		bytes.NewReader(tamperedJSON)))
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered receipt status %d", bad.Code)
	}
	var badResponse verifyResponse
	if err := json.Unmarshal(bad.Body.Bytes(), &badResponse); err != nil {
		t.Fatal(err)
	}
	if badResponse.Verified {
		t.Fatal("tampered receipt accepted")
	}
}

func mustDecode(t *testing.T, data []byte) any {
	t.Helper()
	value, err := DecodeJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
