package agentid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BucketStamp is a customer-key head-stamp written to customer-owned storage.
// It is an alternative to a TSA: the trust root is the customer's key, not us.
type BucketStamp struct {
	HeadSeq   int    `json:"head_seq"`
	HeadHash  string `json:"head_hash"`
	GenTime   string `json:"gen_time"`
	SignerKid string `json:"signer_kid"`
	Alg       string `json:"alg"`
	Signature string `json:"signature"`
}

// Body is the exact signed payload (the signature is excluded).
func (s BucketStamp) Body() map[string]any {
	return map[string]any{
		"head_seq": s.HeadSeq, "head_hash": s.HeadHash,
		"gen_time": s.GenTime, "signer_kid": s.SignerKid, "alg": s.Alg,
	}
}

// NewBucketStamp signs a chain head with the customer's signer.
func NewBucketStamp(head string, seq int, signer Signer) (BucketStamp, error) {
	if len(head) != 64 {
		return BucketStamp{}, errors.New("bucket stamp needs a SHA-256 hex head")
	}
	stamp := BucketStamp{
		HeadSeq: seq, HeadHash: head,
		GenTime:   dateTimeNow().Format(timeLayout),
		SignerKid: signer.Kid(), Alg: "ES256",
	}
	signature, err := signer.Sign(stamp.Body())
	if err != nil {
		return BucketStamp{}, err
	}
	stamp.Signature = signature.Value
	return stamp, nil
}

// WriteBucketStamp writes the stamp into a customer-controlled directory.
func WriteBucketStamp(dir string, stamp BucketStamp) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("head-%08d.json", stamp.HeadSeq))
	data, err := CanonicalJSON(stamp)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// LoadBucketStamp reads a stamp from a file.
func LoadBucketStamp(path string) (BucketStamp, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BucketStamp{}, err
	}
	value, err := DecodeJSON(data)
	if err != nil {
		return BucketStamp{}, err
	}
	raw := AsMap(value)
	return BucketStamp{
		HeadSeq: intValue(raw["head_seq"]), HeadHash: stringField(raw, "head_hash"),
		GenTime: stringField(raw, "gen_time"), SignerKid: stringField(raw, "signer_kid"),
		Alg: stringField(raw, "alg"), Signature: stringField(raw, "signature"),
	}, nil
}

// VerifyBucketStamp checks signature and head binding with only the stamp and
// the published key material — no issuer service or network is involved.
func VerifyBucketStamp(stamp BucketStamp, publicKeys map[string]string,
	expectedHead string) []string {
	problems := []string{}
	if stamp.HeadHash != expectedHead {
		problems = append(problems, "bucket stamp names a different chain head")
	}
	if _, err := time.Parse(timeLayout, stamp.GenTime); err != nil {
		problems = append(problems, "bucket stamp has an invalid gen_time")
	}
	material, ok := publicKeys[stamp.SignerKid]
	if !ok {
		return append(problems, "bucket stamp signer key is not published")
	}
	if stamp.Signature == "" || !VerifySignature(stamp.Alg, material,
		stamp.Body(), stamp.Signature) {
		problems = append(problems, "bucket stamp signature invalid")
	}
	return problems
}

// BucketStampFromMap reconstructs a stamp from stored JSON.
func BucketStampFromMap(raw map[string]any) BucketStamp {
	return BucketStamp{
		HeadSeq: intValue(raw["head_seq"]), HeadHash: stringField(raw, "head_hash"),
		GenTime: stringField(raw, "gen_time"), SignerKid: stringField(raw, "signer_kid"),
		Alg: stringField(raw, "alg"), Signature: stringField(raw, "signature"),
	}
}
