package spireadapter

import (
	"crypto/x509"
)

func x509MarshalPKIX(cert *x509.Certificate) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}
