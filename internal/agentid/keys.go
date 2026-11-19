package agentid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

type ecdsaSignature struct {
	R *big.Int
	S *big.Int
}

// GenerateKeyPair returns PKCS#8 private and PKIX public PEM bytes.
func GenerateKeyPair() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM, err := PublicPEMFromPrivate(key)
	if err != nil {
		return nil, nil, err
	}
	return privatePEM, publicPEM, nil
}

// PublicPEMFromPrivate derives the SPKI PEM matching a private key.
func PublicPEMFromPrivate(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParsePrivatePEM accepts PKCS#8 and SEC1 EC private keys.
func ParsePrivatePEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not ECDSA")
		}
		return ec, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

// ParsePublicPEM accepts PKIX public keys.
func ParsePublicPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}
	return key, nil
}

// KeyFingerprint returns "key_" plus the first 16 hex chars of the PEM digest.
func KeyFingerprint(pemBytes []byte) string {
	return "key_" + DigestSHA256(pemBytes)[:16]
}

// SignRaw produces an unpadded base64url ES256 signature over exact bytes.
// The signature is ASN.1 DER encoded, matching Python `cryptography`.
func SignRaw(key *ecdsa.PrivateKey, data []byte) (string, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return "", err
	}
	der, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}

// VerifyRaw verifies an unpadded base64url DER ES256 signature over exact bytes.
func VerifyRaw(key *ecdsa.PublicKey, data []byte, signature string) bool {
	der, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(der, &sig); err != nil || sig.R == nil || sig.S == nil {
		return false
	}
	hash := sha256.Sum256(data)
	return ecdsa.Verify(key, hash[:], sig.R, sig.S)
}

// Sign signs the canonical JSON of payload.
func Sign(key *ecdsa.PrivateKey, payload any) (string, error) {
	data, err := CanonicalJSON(payload)
	if err != nil {
		return "", err
	}
	return SignRaw(key, data)
}

// Verify verifies a canonical JSON signature.
func Verify(key *ecdsa.PublicKey, payload any, signature string) bool {
	data, err := CanonicalJSON(payload)
	if err != nil {
		return false
	}
	return VerifyRaw(key, data, signature)
}

// Signature is the common artifact shape: alg, key id, and the ES256 value.
type Signature struct {
	Alg   string `json:"alg"`
	Kid   string `json:"kid"`
	Value string `json:"value"`
}

func signatureFromMap(value any) Signature {
	m := AsMap(value)
	if m == nil {
		return Signature{}
	}
	return Signature{
		Alg:   stringField(m, "alg"),
		Kid:   stringField(m, "kid"),
		Value: stringField(m, "value"),
	}
}

func (s Signature) toMap() map[string]any {
	return map[string]any{"alg": s.Alg, "kid": s.Kid, "value": s.Value}
}

func stringField(m map[string]any, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return ""
}

func fmtErr(format string, args ...any) error { return fmt.Errorf(format, args...) }
