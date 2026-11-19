package agentid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const evidenceVersion = "agentid-evidence/v1"

// EvidenceBundle is a portable, self-verifying archive of identity evidence.
// Nothing in it requires the issuer's infrastructure to verify.
type EvidenceBundle struct {
	Version      string
	CreatedAt    string
	Fleet        string
	Receipts     []map[string]any
	Delegations  []map[string]any
	Profile      map[string]any
	Profiles     []map[string]any
	Anchors      []map[string]any
	StatusTokens []string
	SignerKeys   map[string]string
	Manifest     map[string]any
}

func (b EvidenceBundle) body() map[string]any {
	return map[string]any{
		"version": b.Version, "created_at": b.CreatedAt, "fleet": b.Fleet,
		"receipts": b.Receipts, "delegations": b.Delegations,
		"profile": b.Profile, "anchors": b.Anchors,
		"status_tokens": b.StatusTokens,
		"signer_keys":   SignerKeysToMap(b.SignerKeys),
	}
}

// ToMap returns the full bundle including its manifest.
func (b EvidenceBundle) ToMap() map[string]any {
	out := b.body()
	if len(b.Profiles) > 0 {
		out["profiles"] = b.Profiles
	}
	out["manifest"] = b.Manifest
	return out
}

// BuildEvidenceBundle collects receipts, chains, profile, anchors, status
// tokens and the public-key registry into one verifiable artifact.
func BuildEvidenceBundle(fleet string, ledger *Ledger, delegations []Delegation,
	profile Profile, anchors []map[string]any, statusTokens []string,
	extraKeys map[string]string, extraProfiles ...Profile) (EvidenceBundle, error) {
	bundle := EvidenceBundle{
		Version: evidenceVersion, CreatedAt: dateTimeNow().Format(timeLayout),
		Fleet: fleet, Profile: profile.Document(),
		SignerKeys: map[string]string{},
	}
	for _, extra := range extraProfiles {
		bundle.Profiles = append(bundle.Profiles, extra.Document())
	}
	for kid, material := range ledger.SignerKeys {
		bundle.SignerKeys[kid] = material
	}
	for kid, material := range extraKeys {
		bundle.SignerKeys[kid] = material
	}
	for _, receipt := range ledger.Receipts {
		bundle.Receipts = append(bundle.Receipts, receipt.ToMap())
	}
	for _, delegation := range delegations {
		bundle.Delegations = append(bundle.Delegations, delegation.ToMap())
		for kid, material := range delegation.SignerKeys {
			bundle.SignerKeys[kid] = material
		}
	}
	for _, anchor := range anchors {
		bundle.Anchors = append(bundle.Anchors, anchor)
	}
	bundle.StatusTokens = append([]string{}, statusTokens...)
	data, err := CanonicalJSON(bundle.body())
	if err != nil {
		return EvidenceBundle{}, err
	}
	profileDigest, err := profile.Digest()
	if err != nil {
		return EvidenceBundle{}, err
	}
	if len(extraProfiles) > 0 {
		all := append([]Profile{profile}, extraProfiles...)
		profileDigest, err = PolicySetDigest(all)
		if err != nil {
			return EvidenceBundle{}, err
		}
	}
	bundle.Manifest = map[string]any{
		"digest": DigestSHA256(data), "receipt_count": len(bundle.Receipts),
		"delegation_count": len(bundle.Delegations), "anchor_count": len(bundle.Anchors),
		"status_token_count": len(bundle.StatusTokens),
		"profile_digest":     profileDigest,
	}
	return bundle, nil
}

// VerifyEvidenceBundle checks manifest, signatures, chain, profile digests,
// anchors, status tokens and key coverage entirely offline.
func VerifyEvidenceBundle(bundle EvidenceBundle) []string {
	problems := []string{}
	if bundle.Version != evidenceVersion {
		problems = append(problems, "unsupported bundle version: "+bundle.Version)
	}
	data, err := CanonicalJSON(bundle.body())
	if err != nil {
		return append(problems, "bundle not canonicalizable: "+err.Error())
	}
	if got := stringField(bundle.Manifest, "digest"); got != DigestSHA256(data) {
		problems = append(problems, "bundle manifest digest mismatch")
	}
	profile, err := ProfileFromMap(bundle.Profile)
	if err != nil {
		return append(problems, "bundle profile invalid: "+err.Error())
	}
	profileDigest, err := profile.Digest()
	if err != nil {
		return append(problems, "bundle profile digest failed: "+err.Error())
	}
	acceptedProfiles := map[string]bool{profileDigest: true}
	for _, raw := range bundle.Profiles {
		candidate, err := ProfileFromMap(AsMap(raw))
		if err != nil {
			problems = append(problems, "bundled profile invalid: "+err.Error())
			continue
		}
		digest, err := candidate.Digest()
		if err == nil {
			acceptedProfiles[digest] = true
		}
	}
	extraProfiles := bundle.Profiles
	if len(extraProfiles) > 0 {
		all := []Profile{profile}
		for _, raw := range extraProfiles {
			candidate, err := ProfileFromMap(AsMap(raw))
			if err == nil {
				all = append(all, candidate)
			}
		}
		if setDigest, err := PolicySetDigest(all); err == nil {
			acceptedProfiles[setDigest] = true
		}
	}
	if manifestProfile := stringField(bundle.Manifest, "profile_digest"); !acceptedProfiles[manifestProfile] {
		problems = append(problems, "manifest profile digest mismatch")
	}

	delegations := map[string]Delegation{}
	for i, raw := range bundle.Delegations {
		delegation, err := DelegationFromMap(AsMap(raw))
		if err != nil {
			problems = append(problems, fmt.Sprintf("delegation[%d] invalid: %v", i, err))
			continue
		}
		delegations[delegation.ID] = delegation
		if !VerifySignature(delegation.Signature.Alg,
			bundle.SignerKeys[delegation.Signature.Kid],
			delegation.UnsignedBody(), delegation.Signature.Value) {
			problems = append(problems, fmt.Sprintf("delegation[%d] primary signature invalid", i))
		}
		for j, signature := range delegation.Signatures {
			if !VerifySignature(signature.Alg, bundle.SignerKeys[signature.Kid],
				delegation.UnsignedBody(), signature.Value) {
				problems = append(problems, fmt.Sprintf(
					"delegation[%d] additional signature[%d] invalid", i, j))
			}
		}
	}

	ledger := &Ledger{SignerKeys: bundle.SignerKeys}
	for i, raw := range bundle.Receipts {
		receipt := ReceiptFromMap(AsMap(raw))
		if err := ledger.Append(&receipt); err != nil {
			problems = append(problems, fmt.Sprintf("receipt[%d] broken chain link: %v", i, err))
			continue
		}
		decision := AsMap(receipt.Decision)
		if got := stringField(decision, "profile_digest"); !acceptedProfiles[got] {
			problems = append(problems, fmt.Sprintf(
				"receipt[%d] does not name the bundled profile", i))
		}
		if _, ok := delegations[receipt.DelegationID]; !ok {
			problems = append(problems, fmt.Sprintf(
				"receipt[%d] references missing delegation %s", i, receipt.DelegationID))
		}
	}
	problems = append(problems, ledger.VerifyChain(bundle.SignerKeys)...)

	for i, anchor := range bundle.Anchors {
		problems = append(problems, prefixProblems(
			fmt.Sprintf("anchor[%d]", i), VerifyAnchorBinding(anchor))...)
	}
	for i, token := range bundle.StatusTokens {
		if err := verifyArchivedStatusToken(token, bundle.SignerKeys); err != nil {
			problems = append(problems, fmt.Sprintf("status_token[%d]: %v", i, err))
		}
	}
	return problems
}

// VerifyAnchorBinding checks a stamp's request/response binding at any head,
// including historical anchors whose head is no longer the chain tip.
func VerifyAnchorBinding(record map[string]any) []string {
	problems := []string{}
	response, err := base64.StdEncoding.DecodeString(stringField(record, "response_der_b64"))
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	info, err := ParseTimestampResp(response)
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	head := stringField(record, "head_hash")
	if info.MessageImprint != head {
		problems = append(problems, "TSTInfo names a different digest")
	}
	stored, err := base64.StdEncoding.DecodeString(stringField(record, "request_der_b64"))
	if err != nil {
		return append(problems, "anchor unparsable: "+err.Error())
	}
	expected, err := BuildTimestampReq(head)
	if err != nil || !bytes.Equal(stored, expected) {
		problems = append(problems, "stored request does not match the recorded head hash")
	}
	return problems
}

func verifyArchivedStatusToken(token string, keys map[string]string) error {
	parts := splitToken(token)
	if len(parts) != 3 {
		return errors.New("malformed statuslist+jwt")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payloadJSON))
	decoder.UseNumber()
	var payload map[string]any
	if err := decoder.Decode(&payload); err != nil {
		return err
	}
	iat := intValue(payload["iat"])
	ttl := intValue(payload["ttl"])
	if ttl <= 0 {
		ttl = 1 << 30
	}
	_, err = VerifyStatusToken(token, keys, iat, ttl)
	return err
}

func prefixProblems(prefix string, problems []string) []string {
	out := make([]string, 0, len(problems))
	for _, problem := range problems {
		out = append(out, prefix+": "+problem)
	}
	return out
}

// WriteBundle writes a bundle as canonical JSONL-compatible single JSON.
func WriteBundle(path string, bundle EvidenceBundle) error {
	data, err := CanonicalJSON(bundle.ToMap())
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// LoadEvidenceBundle reads a bundle from disk.
func LoadEvidenceBundle(path string) (EvidenceBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EvidenceBundle{}, err
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return EvidenceBundle{}, err
	}
	return evidenceBundleFromMap(AsMap(value)), nil
}

func evidenceBundleFromMap(raw map[string]any) EvidenceBundle {
	bundle := EvidenceBundle{
		Version: stringField(raw, "version"), CreatedAt: stringField(raw, "created_at"),
		Fleet: stringField(raw, "fleet"), Profile: AsMap(raw["profile"]),
		Manifest: AsMap(raw["manifest"]), SignerKeys: map[string]string{},
	}
	for kid, material := range AsMap(raw["signer_keys"]) {
		bundle.SignerKeys[kid] = stringValue(material)
	}
	for _, item := range AsSlice(raw["receipts"]) {
		bundle.Receipts = append(bundle.Receipts, AsMap(item))
	}
	for _, item := range AsSlice(raw["delegations"]) {
		bundle.Delegations = append(bundle.Delegations, AsMap(item))
	}
	for _, item := range AsSlice(raw["profiles"]) {
		bundle.Profiles = append(bundle.Profiles, AsMap(item))
	}
	for _, item := range AsSlice(raw["anchors"]) {
		bundle.Anchors = append(bundle.Anchors, AsMap(item))
	}
	for _, item := range AsSlice(raw["status_tokens"]) {
		bundle.StatusTokens = append(bundle.StatusTokens, stringValue(item))
	}
	return bundle
}

// EvidenceStore is the custody boundary: the issuer writes, never reads back
// through our infrastructure.
type EvidenceStore interface {
	Put(bundle EvidenceBundle) (string, error)
}

// LocalStore writes bundles to a customer-controlled directory.
type LocalStore struct{ Dir string }

func (s LocalStore) Put(bundle EvidenceBundle) (string, error) {
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return "", err
	}
	digest := stringField(bundle.Manifest, "digest")
	if len(digest) < 16 {
		digest = DigestSHA256([]byte(bundle.CreatedAt))
	}
	path := filepath.Join(s.Dir, "evidence-"+digest[:16]+".json")
	if err := WriteBundle(path, bundle); err != nil {
		return "", err
	}
	return path, nil
}

// PresignedURLStore writes to S3/GCS via a customer-provided presigned URL.
// Object-lock/retention policy is configured at the provider, not in code.
type PresignedURLStore struct {
	URL    string
	Client *http.Client
}

func (s PresignedURLStore) Put(bundle EvidenceBundle) (string, error) {
	data, err := CanonicalJSON(bundle.ToMap())
	if err != nil {
		return "", err
	}
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	request, err := http.NewRequest(http.MethodPut, s.URL, strings.NewReader(string(data)))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("evidence store returned HTTP %d", response.StatusCode)
	}
	return s.URL, nil
}
