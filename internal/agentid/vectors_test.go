package agentid

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validationAt = "2026-11-20T00:00:00Z"

func loadVectors(t *testing.T) map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return root
}

func TestCanonVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range AsSlice(vectors["canon"]) {
		entry := AsMap(item)
		data, err := CanonicalJSON(entry["value"])
		if err != nil {
			t.Fatalf("canonicalize %v: %v", entry["value"], err)
		}
		if got := DigestSHA256(data); got != stringValue(entry["hex"]) {
			t.Errorf("hex digest mismatch: got %s want %s", got, entry["hex"])
		}
		if got := B64URLDigestSHA256(data); got != stringValue(entry["b64url"]) {
			t.Errorf("b64url digest mismatch: got %s want %s", got, entry["b64url"])
		}
	}
}

func TestEnvelopeVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range AsSlice(vectors["envelopes"]) {
		entry := AsMap(item)
		request := AsMap(entry["request"])
		digest, err := EnvelopeDigest(request)
		if err != nil {
			t.Fatalf("envelope digest: %v", err)
		}
		if digest != stringValue(entry["digest"]) {
			t.Errorf("envelope digest mismatch: got %s want %s", digest, entry["digest"])
		}
		envelope, err := BuildEnvelope(request)
		if err != nil {
			t.Fatalf("build envelope: %v", err)
		}
		want := AsMap(entry["envelope"])
		got, err := CanonicalJSON(envelope.ToMap())
		if err != nil {
			t.Fatal(err)
		}
		expected, err := CanonicalJSON(want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, expected) {
			t.Errorf("envelope shape mismatch for %v", request["action"])
		}
	}
}

func TestPythonSignatureVerifiesInGo(t *testing.T) {
	vectors := loadVectors(t)
	entry := AsMap(vectors["crypto"])
	key, err := ParsePublicPEM([]byte(stringValue(entry["public_pem"])))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if !Verify(key, AsMap(entry["payload"]), stringValue(entry["signature"])) {
		t.Fatal("Python-produced ES256 signature did not verify in Go")
	}
}

func TestDecisionVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range AsSlice(vectors["decisions"]) {
		entry := AsMap(item)
		name := stringValue(entry["name"])
		t.Run(name, func(t *testing.T) {
			profile, err := ProfileFromMap(AsMap(entry["profile"]))
			if err != nil {
				t.Fatalf("profile: %v", err)
			}
			var chain []Delegation
			for _, raw := range AsSlice(entry["chain"]) {
				delegation, err := DelegationFromMap(AsMap(raw))
				if err != nil {
					t.Fatalf("delegation: %v", err)
				}
				chain = append(chain, delegation)
			}
			ledger := &Ledger{}
			for _, raw := range AsSlice(entry["seeds"]) {
				seed := AsMap(raw)
				previous := strings.Repeat("0", 64)
				if len(ledger.Receipts) > 0 {
					hash, err := ledger.Receipts[len(ledger.Receipts)-1].Hash()
					if err != nil {
						t.Fatal(err)
					}
					previous = hash
				}
				receipt := &Receipt{
					ID: "", IssuedAt: stringValue(seed["issued_at"]), Fleet: "v",
					Actor: map[string]any{}, DelegationID: "seed", Action: "seed",
					Resource: map[string]any{
						"type": "t", "id": "i", "attributes": AsMap(seed["attributes"]),
					},
					Decision:   map[string]any{"result": "allowed"},
					Outcome:    map[string]any{},
					ActionType: "observed", PrevHash: previous,
				}
				if err := ledger.Append(receipt); err != nil {
					t.Fatalf("seed receipt: %v", err)
				}
			}
			opts := ValidationOptions{
				Ledger: ledger, Approval: AsMap(entry["approval"]), At: validationAt,
			}
			if entry["status_lookup"] != nil {
				status := intValue(entry["status_lookup"])
				opts.StatusLookup = func(uri string, idx int) (int, error) { return status, nil }
			}
			result := Validate(chain, AsMap(entry["action"]), profile,
				[]byte(stringValue(entry["root_pub"])), opts)
			expect := AsMap(entry["expect"])
			want := stringValue(expect["outcome"])
			if result.Outcome != want {
				t.Fatalf("outcome: got %q want %q (reason: %s)", result.Outcome, want, result.Reason)
			}
			for _, raw := range AsSlice(expect["reason_contains"]) {
				if !strings.Contains(result.Reason, stringValue(raw)) {
					t.Errorf("reason %q missing %q", result.Reason, raw)
				}
			}
		})
	}
}

func mustMarshal(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func TestStatusVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, item := range AsSlice(vectors["status"]) {
		entry := AsMap(item)
		var statuses []int
		for _, raw := range AsSlice(entry["statuses"]) {
			statuses = append(statuses, intValue(raw))
		}
		pythonEncoded := AsMap(entry["encoded"])
		decoded, err := DecodeStatusList(pythonEncoded, len(statuses))
		if err != nil {
			t.Fatalf("decode Python status list: %v", err)
		}
		if len(decoded) != len(statuses) {
			t.Fatalf("decoded length %d want %d", len(decoded), len(statuses))
		}
		for i := range statuses {
			if decoded[i] != statuses[i] {
				t.Errorf("status[%d]: got %d want %d", i, decoded[i], statuses[i])
			}
		}
		goEncoded, err := EncodeStatusList(statuses, 2)
		if err != nil {
			t.Fatalf("encode Go status list: %v", err)
		}
		roundTrip, err := DecodeStatusList(goEncoded, len(statuses))
		if err != nil {
			t.Fatalf("decode Go status list: %v", err)
		}
		for i := range statuses {
			if roundTrip[i] != statuses[i] {
				t.Errorf("Go round-trip status[%d]: got %d want %d", i, roundTrip[i], statuses[i])
			}
		}
	}

	tokens := AsMap(vectors["status_tokens"])
	keys := map[string]string{}
	for kid, pem := range AsMap(tokens["public_keys"]) {
		keys[kid] = stringValue(pem)
	}
	now := intValue(tokens["now"])
	maxAge := intValue(tokens["max_status_age"])
	fresh := stringValue(tokens["fresh"])
	if _, err := VerifyStatusToken(fresh, keys, now, maxAge); err != nil {
		t.Fatalf("verify Python status token: %v", err)
	}
	status, err := CheckStatus(fresh, 1, keys, maxAge, now)
	if err != nil {
		t.Fatalf("check status: %v", err)
	}
	if status != intValue(tokens["status_at_1"]) {
		t.Errorf("status at index 1: got %d want %v", status, tokens["status_at_1"])
	}
	if _, err := VerifyStatusToken(stringValue(tokens["stale"]), keys, now, maxAge); err == nil {
		t.Fatal("stale status token was accepted")
	}
}
