package agentid

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// Signer is the credential boundary: the agent never holds a private key.
type Signer interface {
	Sign(payload any) (Signature, error)
	SignRaw(data []byte) (string, error)
	PublicKey(kid string) (string, error)
	PublicKeys() map[string]string
	Kid() string
}

type signerBase struct {
	key    *ecdsa.PrivateKey
	pubPEM string
	kid    string
}

func newSignerBase(privatePEM, publicPEM []byte, kid string) (signerBase, error) {
	key, err := ParsePrivatePEM(privatePEM)
	if err != nil {
		return signerBase{}, err
	}
	derived, err := PublicPEMFromPrivate(key)
	if err != nil {
		return signerBase{}, err
	}
	if len(publicPEM) > 0 && string(derived) != string(publicPEM) {
		return signerBase{}, errors.New("public key does not match private key")
	}
	if kid == "" {
		kid = KeyFingerprint(derived)
	}
	return signerBase{key: key, pubPEM: string(derived), kid: kid}, nil
}

func (s signerBase) Sign(payload any) (Signature, error) {
	value, err := Sign(s.key, payload)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: "ES256", Kid: s.kid, Value: value}, nil
}

func (s signerBase) SignRaw(data []byte) (string, error) {
	return SignRaw(s.key, data)
}

func (s signerBase) PublicKey(kid string) (string, error) {
	if kid != s.kid {
		return "", fmt.Errorf("unknown key id %q", kid)
	}
	return s.pubPEM, nil
}

func (s signerBase) PublicKeys() map[string]string {
	return map[string]string{s.kid: s.pubPEM}
}

func (s signerBase) Kid() string { return s.kid }

// DevSigner is a local PEM signer — NOT FOR PRODUCTION.
type DevSigner struct{ signerBase }

// NewDevSigner creates a labeled development signer.
func NewDevSigner(privatePEM, publicPEM []byte, kid string) (*DevSigner, error) {
	base, err := newSignerBase(privatePEM, publicPEM, kid)
	if err != nil {
		return nil, err
	}
	return &DevSigner{base}, nil
}

// ExternalSigner wraps a KMS/HSM sign callable; no private key is held here.
type ExternalSigner struct {
	kid    string
	pubPEM string
	signFn func([]byte) ([]byte, error)
}

// NewExternalSigner creates a KMS/HSM adapter signer.
func NewExternalSigner(kid, publicPEM string, signFn func([]byte) ([]byte, error)) *ExternalSigner {
	return &ExternalSigner{kid: kid, pubPEM: publicPEM, signFn: signFn}
}

func (s *ExternalSigner) Kid() string { return s.kid }

func (s *ExternalSigner) Sign(payload any) (Signature, error) {
	data, err := CanonicalJSON(payload)
	if err != nil {
		return Signature{}, err
	}
	value, err := s.SignRaw(data)
	if err != nil {
		return Signature{}, err
	}
	return Signature{Alg: "ES256", Kid: s.kid, Value: value}, nil
}

func (s *ExternalSigner) SignRaw(data []byte) (string, error) {
	raw, err := s.signFn(data)
	if err != nil {
		return "", err
	}
	return base64RawURL(raw), nil
}

func (s *ExternalSigner) PublicKey(kid string) (string, error) {
	if kid != s.kid {
		return "", fmt.Errorf("unknown key id %q", kid)
	}
	return s.pubPEM, nil
}

func (s *ExternalSigner) PublicKeys() map[string]string { return map[string]string{s.kid: s.pubPEM} }

// RotatingSigner signs with the current key and verifies retired keys during overlap.
type RotatingSigner struct{ signers []Signer }

// NewRotatingSigner takes the current signer first, then retired signers.
func NewRotatingSigner(signers []Signer) (*RotatingSigner, error) {
	if len(signers) == 0 {
		return nil, errors.New("RotatingSigner needs at least one signer")
	}
	return &RotatingSigner{signers: signers}, nil
}

func (s *RotatingSigner) Kid() string { return s.signers[0].Kid() }

func (s *RotatingSigner) Sign(payload any) (Signature, error) {
	signature, err := s.signers[0].Sign(payload)
	if err != nil {
		return Signature{}, err
	}
	signature.Kid = s.Kid()
	return signature, nil
}

func (s *RotatingSigner) SignRaw(data []byte) (string, error) {
	return s.signers[0].SignRaw(data)
}

func (s *RotatingSigner) PublicKey(kid string) (string, error) {
	for _, signer := range s.signers {
		if signer.Kid() == kid {
			return signer.PublicKey(kid)
		}
	}
	return "", fmt.Errorf("unknown key id %q", kid)
}

func (s *RotatingSigner) PublicKeys() map[string]string {
	keys := map[string]string{}
	for _, signer := range s.signers {
		for kid, pem := range signer.PublicKeys() {
			keys[kid] = pem
		}
	}
	return keys
}

// DualSign signs one payload under several algorithms without changing shape.
func DualSign(payload any, signers []Signer) ([]Signature, error) {
	result := make([]Signature, 0, len(signers))
	for _, signer := range signers {
		signature, err := signer.Sign(payload)
		if err != nil {
			return nil, err
		}
		result = append(result, signature)
	}
	return result, nil
}
