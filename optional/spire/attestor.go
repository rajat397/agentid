// Package spireadapter attests workloads through a SPIRE agent's Workload API.
// It is an optional module: the core agentid module has no third-party deps.
package spireadapter

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rajat397/agentid/attest"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Attestor fetches an X509-SVID from the local SPIRE agent and projects it
// into an agentid attestation.
type Attestor struct {
	SocketPath          string
	ExpectedTrustDomain string
	ValidFor            time.Duration
}

// Attest implements attest.Attestor.
func (a Attestor) Attest() (attest.Attestation, error) {
	options := []workloadapi.ClientOption{}
	if a.SocketPath != "" {
		options = append(options, workloadapi.WithAddr("unix://"+a.SocketPath))
	}
	svid, err := workloadapi.FetchX509SVID(context.Background(), options...)
	if err != nil {
		return attest.Attestation{}, fmt.Errorf("SPIRE Workload API: %w", err)
	}
	spiffeID := svid.ID.String()
	domain := svid.ID.TrustDomain().String()
	if a.ExpectedTrustDomain != "" && domain != a.ExpectedTrustDomain {
		return attest.Attestation{}, fmt.Errorf(
			"unexpected SPIFFE trust domain %q (want %q)", domain, a.ExpectedTrustDomain)
	}
	if len(svid.Certificates) == 0 {
		return attest.Attestation{}, fmt.Errorf("X509-SVID has no certificate")
	}
	cert := svid.Certificates[0]
	credentialDER, err := x509MarshalPKIX(cert)
	if err != nil {
		return attest.Attestation{}, err
	}
	validUntil := cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	if a.ValidFor > 0 {
		validUntil = time.Now().UTC().Add(a.ValidFor).Format("2006-01-02T15:04:05Z")
	}
	return attest.Attestation{
		SPIFFEID:        spiffeID,
		CredentialDigest: attest.CredentialDigest(credentialDER),
		TrustDomain:     strings.TrimSuffix(domain, "/"),
		ValidUntil:      validUntil,
		Evidence:        "SPIRE X509-SVID via Workload API (trust domain " + domain + ")",
	}, nil
}
