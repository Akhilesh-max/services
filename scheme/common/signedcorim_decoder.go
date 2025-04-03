// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package common

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/veraison/corim/corim"
	"github.com/veraison/go-cose"
	"github.com/veraison/services/handler"
)

// SignedCorimDecoder processes a signed CoRIM, verifies its signature, and then
// passes the unsigned CoRIM to the UnsignedCorimDecoder for further processing.
func SignedCorimDecoder(
	data []byte,
	xtr IExtractor,
	caCertPoolPEM []byte,
) (*handler.EndorsementHandlerResponse, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// Parse the signed CoRIM
	sc := corim.NewSignedCorim()
	if err := sc.FromCOSE(data); err != nil {
		return nil, fmt.Errorf("failed to parse signed CoRIM: %w", err)
	}

	// Load CA certificates from PEM
	certPool := x509.NewCertPool()
	if len(caCertPoolPEM) > 0 {
		if !certPool.AppendCertsFromPEM(caCertPoolPEM) {
			return nil, errors.New("failed to parse CA certificates")
		}
	}

	// Extract the certificates from the COSE Sign1 message and verify them
	// Decode the COSE Sign1 message directly to access headers
	var sign1 cose.Sign1Message
	if err := sign1.UnmarshalCBOR(data); err != nil {
		return nil, fmt.Errorf("failed to decode COSE Sign1 message: %w", err)
	}

	if err := sign1.Headers.UnmarshalFromRaw(); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE headers: %w", err)
	}

	// Check for certificate chain in the protected header using X5Chain (label 33)
	headerVal, ok := sign1.Headers.Protected[cose.HeaderLabelX5Chain]
	if ok {
		certChain, hasChain := extractCertificateChain(headerVal)
		if hasChain && len(certChain) > 0 {
			certs := make([]*x509.Certificate, 0, len(certChain))
			for i, certBytes := range certChain {
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse certificate at index %d: %w", i, err)
				}
				certs = append(certs, cert)
			}

			if len(certs) > 0 {
				// Leaf certificate is the first one in the chain
				leafCert := certs[0]

				// Add other certificates as intermediates
				intermediates := x509.NewCertPool()
				for i := 1; i < len(certs); i++ {
					intermediates.AddCert(certs[i])
				}

				// Verify the certificate chain
				opts := x509.VerifyOptions{
					Roots:         certPool,
					Intermediates: intermediates,
				}

				_, err := leafCert.Verify(opts)
				if err != nil {
					return nil, fmt.Errorf("certificate chain verification failed: %w", err)
				}

				if err := sc.Verify(leafCert.PublicKey); err != nil {
					return nil, fmt.Errorf("signature verification failed: %w", err)
				}
			}
		}
	}

	unsignedCorimCBOR, err := sc.UnsignedCorim.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to extract unsigned CoRIM: %w", err)
	}

	return UnsignedCorimDecoder(unsignedCorimCBOR, xtr)
}

// extractCertificateChain tries to extract a certificate chain from a COSE header value
func extractCertificateChain(headerVal interface{}) ([][]byte, bool) {
	switch v := headerVal.(type) {
	case []byte:
		return [][]byte{v}, true
	case [][]byte:
		return v, true
	}
	return nil, false
}
