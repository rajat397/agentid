package agentid

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// KeyInfo is one published verification key. `format` is "pem" for ES256 and
// "raw-b64url" for ML-DSA-65 FIPS 204 public keys.
type KeyInfo struct {
	Kid      string `json:"kid"`
	Alg      string `json:"alg"`
	Material string `json:"material"`
	Format   string `json:"format"`
}

type checkResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type verifyResponse struct {
	Verified bool          `json:"verified"`
	Checks   []checkResult `json:"checks"`
	Reason   string        `json:"reason,omitempty"`
}

// InferKeyInfo classifies public key material held in a signer key registry.
func InferKeyInfo(kid, material string) KeyInfo {
	if strings.Contains(material, "BEGIN PUBLIC KEY") {
		return KeyInfo{Kid: kid, Alg: "ES256", Material: material, Format: "pem"}
	}
	if len(material) > 1000 {
		return KeyInfo{Kid: kid, Alg: AlgMLDSA65, Material: material, Format: "raw-b64url"}
	}
	return KeyInfo{Kid: kid, Alg: "unknown", Material: material, Format: "unknown"}
}

// NewVerificationHandler mounts /receipts/verify and /v1/keys on caller-owned
// infrastructure. It performs no outbound network calls.
func NewVerificationHandler(keys map[string]string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list := []KeyInfo{}
		for kid, material := range keys {
			list = append(list, InferKeyInfo(kid, material))
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": list})
	})
	mux.HandleFunc("/receipts/verify", func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		var err error
		if r.Method == http.MethodPost {
			raw, err = io.ReadAll(io.LimitReader(r.Body, 1<<20))
		} else if r.Method == http.MethodGet {
			raw = []byte(r.URL.Query().Get("receipt"))
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		value, err := DecodeJSON(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, verifyResponse{
				Reason: "receipt is not valid JSON", Checks: []checkResult{},
			})
			return
		}
		receipt := ReceiptFromMap(AsMap(value))
		response := VerifyReceiptExternal(receipt, keys)
		status := http.StatusOK
		if !response.Verified {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, response)
	})
	return mux
}

// VerifyReceiptExternal checks a receipt using only the receipt bytes and the
// published key set — no ledger, no service round-trip.
func VerifyReceiptExternal(receipt Receipt, keys map[string]string) verifyResponse {
	checks := []checkResult{}
	add := func(name string, ok bool, detail string) { checks = append(checks, checkResult{name, ok, detail}) }

	bodyHash, err := receipt.Hash()
	add("body_hash", err == nil, errString(err))
	if receipt.ID == "" {
		add("receipt_id", false, "missing receipt id")
	} else {
		add("receipt_id", receipt.ID == "rcp_"+bodyHash[:16], "id must be the body digest prefix")
	}
	decision := AsMap(receipt.Decision)
	profileDigest := stringField(decision, "profile_digest")
	add("profile_digest", len(profileDigest) == 43 || len(profileDigest) == 64,
		"receipt must name a SHA-256 profile digest (base64url or hex)")
	envelopeDigest := stringField(decision, "envelope_digest")
	add("envelope_digest", len(envelopeDigest) == 64, "receipt must name the action envelope digest")

	if receipt.Signature == nil {
		add("primary_signature", false, "receipt is unsigned")
	} else {
		material, ok := keys[receipt.Signature.Kid]
		if !ok {
			add("primary_signature", false, "kid not published")
		} else {
			add("primary_signature", VerifySignature(receipt.Signature.Alg,
				material, receipt.Body(), receipt.Signature.Value), receipt.Signature.Alg)
		}
	}
	for i, signature := range receipt.Signatures {
		material, ok := keys[signature.Kid]
		if !ok {
			add("additional_signature_"+itoa(i), false, "kid not published")
			continue
		}
		add("additional_signature_"+itoa(i),
			VerifySignature(signature.Alg, material, receipt.Body(), signature.Value),
			signature.Alg)
	}
	verified := true
	reason := ""
	for _, check := range checks {
		if !check.OK {
			verified = false
			reason = check.Name + ": " + check.Detail
			break
		}
	}
	return verifyResponse{Verified: verified, Checks: checks, Reason: reason}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
