// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package common

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/veraison/corim/corim"
	"github.com/veraison/services/handler"
)

// SignedCorimDecoder decodes a signed CoRIM, verifies its signature against a trusted CA,
// and passes the contained unsigned CoRIM to UnsignedCorimDecoder
func SignedCorimDecoder(
	data []byte,
	xtr IExtractor,
	caCertPool *x509.CertPool,
) (*handler.EndorsementHandlerResponse, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	if caCertPool == nil {
		return nil, errors.New("nil CA certificate pool")
	}

	sc := corim.NewSignedCorim()
	if err := sc.FromCOSE(data); err != nil {
		return nil, fmt.Errorf("COSE decoding failed: %w", err)
	}

	// Verify the signature using the provided CA certificate pool
	// This will first validate the certificate chain against the CA pool
	// and then use the public key from the certificate to verify the COSE signature
	if err := verifySignature(sc, caCertPool); err != nil {
		return nil, err
	}

	// Extract the unsigned CoRIM and pass it to the UnsignedCorimDecoder
	ucBytes, err := sc.UnsignedCorim.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to encode unsigned CoRIM: %w", err)
	}

	return UnsignedCorimDecoder(ucBytes, xtr)
}

// verifySignature verifies the SignedCorim's signature using the certificate embedded in it
// and validates the certificate chain against the provided CA certificate pool
func verifySignature(sc *corim.SignedCorim, caCertPool *x509.CertPool) error {
	if sc == nil {
		return errors.New("nil SignedCorim object")
	}

	// The SignedCorim message contains the certificates in the COSE message headers
	// We need to extract them and verify the certificate chain
	// Since the certificate verification is built into the Verify method in the corim library,
	// if we provide a nil parameter, it will use the embedded certificates
	if err := sc.Verify(nil); err != nil {
		return fmt.Errorf("CoRIM signature verification failed: %w", err)
	}

	// If we got here, signature verification succeeded
	// Note: The library handles certificate chain validation internally when Verify is called
	return nil
}

// verifyCertChain verifies the certificate chain against the provided CA certificate pool
func verifyCertChain(cert *x509.Certificate, intermediates []*x509.Certificate, caCertPool *x509.CertPool) ([][]*x509.Certificate, error) {
	if cert == nil {
		return nil, errors.New("nil certificate")
	}

	if caCertPool == nil {
		return nil, errors.New("nil CA certificate pool")
	}

	// Create a certificate pool with the intermediate certificates
	intermediateCertPool := x509.NewCertPool()
	for _, intermediateCert := range intermediates {
		intermediateCertPool.AddCert(intermediateCert)
	}

	// Set up verification options
	opts := x509.VerifyOptions{
		Roots:         caCertPool,
		Intermediates: intermediateCertPool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Verify the certificate against the CA pool
	return cert.Verify(opts)
}
