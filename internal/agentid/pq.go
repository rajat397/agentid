package agentid

import (
	"crypto/ecdsa"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// AlgMLDSA65 is the post-quantum signature algorithm from FIPS 204.
const AlgMLDSA65 = "ML-DSA-65"

// PQSigner signs with ML-DSA-65. Public keys are published as unpadded
// base64url raw FIPS 204 encodings, not PEM (see Signer.PublicKeys).
type PQSigner struct {
	private *mldsa.PrivateKey
	kid     string
}

// NewPQSigner generates an ML-DSA-65 key pair.
func NewPQSigner(kid string) (*PQSigner, error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, err
	}
	if kid == "" {
		kid = KeyFingerprint(key.PublicKey().Bytes())
	}
	return &PQSigner{private: key, kid: kid}, nil
}

func (s *PQSigner) Kid() string { return s.kid }

func (s *PQSigner) Sign(payload any) (Signature, error) {
	data, err := CanonicalJSON(payload)
	if err != nil {
		return Signature{}, err
	}
	value, err := s.SignRaw(data)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: AlgMLDSA65, Kid: s.kid, Value: value}, nil
}

func (s *PQSigner) SignRaw(data []byte) (string, error) {
	signature, err := s.private.Sign(rand.Reader, data, nil)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(signature), nil
}

func (s *PQSigner) PublicKey(kid string) (string, error) {
	if kid != s.kid {
		return "", fmt.Errorf("unknown key id %q", kid)
	}
	return base64.RawURLEncoding.EncodeToString(s.private.PublicKey().Bytes()), nil
}

func (s *PQSigner) PublicKeys() map[string]string {
	return map[string]string{s.kid: base64.RawURLEncoding.EncodeToString(s.private.PublicKey().Bytes())}
}

var (
	defaultPQOnce sync.Once
	defaultPQ     *PQSigner
	defaultPQErr  error
)

// DefaultPQSigner is a process-wide development PQ key. Production callers
// must inject a stable KMS/HSM-backed PQSigner instead — this key does not
// survive a process restart and must not be used as a long-term trust anchor.
func DefaultPQSigner() (*PQSigner, error) {
	defaultPQOnce.Do(func() {
		defaultPQ, defaultPQErr = NewPQSigner("dev_pq_key")
	})
	return defaultPQ, defaultPQErr
}

// VerifySignature dispatches verification by algorithm. `publicMaterial` is
// a PEM for ES256 and unpadded base64url FIPS 204 bytes for ML-DSA-65.
func VerifySignature(alg, publicMaterial string, payload any, value string) bool {
	key, err := parseSignaturePublicKey(alg, publicMaterial)
	if err != nil {
		return false
	}
	return verifyWithParsedKey(alg, key, payload, value)
}

func VerifySignatureRaw(alg, publicMaterial string, data []byte, value string) bool {
	key, err := parseSignaturePublicKey(alg, publicMaterial)
	if err != nil {
		return false
	}
	return verifyRawWithParsedKey(alg, key, data, value)
}

func parseSignaturePublicKey(alg, material string) (any, error) {
	switch alg {
	case "ES256":
		return ParsePublicPEM([]byte(material))
	case AlgMLDSA65:
		raw, err := base64.RawURLEncoding.DecodeString(material)
		if err != nil {
			return nil, err
		}
		return mldsa.NewPublicKey(mldsa.MLDSA65(), raw)
	default:
		return nil, errors.New("unsupported signature algorithm: " + alg)
	}
}

func verifyWithParsedKey(alg string, key any, payload any, value string) bool {
	data, err := CanonicalJSON(payload)
	if err != nil {
		return false
	}
	return verifyRawWithParsedKey(alg, key, data, value)
}

func verifyRawWithParsedKey(alg string, key any, data []byte, value string) bool {
	switch alg {
	case "ES256":
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return VerifyRaw(ecdsaKey, data, value)
	case AlgMLDSA65:
		pqKey, ok := key.(*mldsa.PublicKey)
		if !ok {
			return false
		}
		raw, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil {
			return false
		}
		return mldsa.Verify(pqKey, data, raw, nil) == nil
	}
	return false
}
