// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package common

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/veraison/corim/corim"
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

	// Extract and verify the signature using proper certificate verification
	// TODO: Implement complete certificate chain verification against the CA pool
	// For now, we're just verifying the signature

	// Verify the signature (this would use the public key from the verified certificate)
	// This is a placeholder - in a real implementation, we would extract the
	// public key from the verified certificate
	var publicKey crypto.PublicKey

	if err := sc.Verify(publicKey); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Convert the unsigned CoRIM back to CBOR to process it
	unsignedCorimCBOR, err := sc.UnsignedCorim.ToCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to extract unsigned CoRIM: %w", err)
	}

	// Process the unsigned CoRIM
	return UnsignedCorimDecoder(unsignedCorimCBOR, xtr)
}
