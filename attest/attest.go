// Package attest defines the workload-attestation boundary for agent
// identities. Implementations range from a labeled dev attestor to a SPIRE
// Workload API adapter (optional module, kept out of the core dependency set).
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// Attestation binds a verified workload identity to a credential.
type Attestation struct {
	SPIFFEID         string `json:"spiffe_id"`
	CredentialDigest string `json:"credential_digest"`
	TrustDomain      string `json:"trust_domain"`
	ValidUntil       string `json:"valid_until"`
	Evidence         string `json:"evidence"`
}

// Attestor issues a fresh attestation for the workload it represents.
type Attestor interface {
	Attest() (Attestation, error)
}

// CredentialDigest is the SHA-256 of a public key's canonical bytes.
func CredentialDigest(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// DevAttestor is a local, labeled development attestor — NOT FOR PRODUCTION.
// It binds an actor ID and public key without verifying the workload.
type DevAttestor struct {
	SPIFFEID  string
	PublicKey []byte
	ValidFor  time.Duration
}

// Attest returns a deterministic, short-lived development attestation.
func (d DevAttestor) Attest() (Attestation, error) {
	validFor := d.ValidFor
	if validFor <= 0 {
		validFor = 15 * time.Minute
	}
	return Attestation{
		SPIFFEID:         d.SPIFFEID,
		CredentialDigest: CredentialDigest(d.PublicKey),
		TrustDomain:      "example.trust",
		ValidUntil:       time.Now().UTC().Add(validFor).Format("2006-01-02T15:04:05Z"),
		Evidence:         "dev-attestor (NOT FOR PRODUCTION)",
	}, nil
}
