// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsec_cca

import (
	"crypto/x509"
	"strings"

	"github.com/veraison/services/handler"
	"github.com/veraison/services/scheme/common"
)

type EndorsementHandler struct{}

func (o EndorsementHandler) Init(params handler.EndorsementHandlerParams) error {
	return nil // no-op
}

func (o EndorsementHandler) Close() error {
	return nil // no-op
}

func (o EndorsementHandler) GetName() string {
	return "unsigned-corim (Parsec CCA profile)"
}

func (o EndorsementHandler) GetAttestationScheme() string {
	return SchemeName
}

func (o EndorsementHandler) GetSupportedMediaTypes() []string {
	return EndorsementMediaTypes
}

func (o EndorsementHandler) Decode(data []byte, mediaType string, caCertPool *x509.CertPool) (*handler.EndorsementHandlerResponse, error) {
	// Check if this is a signed CoRIM based on media type
	if strings.Contains(mediaType, "corim-signed") {
		// Handle signed CoRIM
		return common.SignedCorimDecoder(data, &ParsecCcaExtractor{}, caCertPool)
	}

	// Handle unsigned CoRIM
	return common.UnsignedCorimDecoder(data, &ParsecCcaExtractor{})
}
