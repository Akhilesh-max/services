// Copyright 2022-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package handler

import (
	"crypto/x509"

	"github.com/veraison/services/plugin"
)

// EndorsementHandlerParams are passed to IEndorsementHandler.Init() They are
// implementation-specific.
type EndorsementHandlerParams map[string]interface{}

// IEndorsementHandler defines the interface to functionality for working with
// attestation scheme specific endorsement provisioning tokens (typically,
// CoRIM's).
type IEndorsementHandler interface {
	plugin.IPluggable

	// Init() initializes the handler.
	Init(params EndorsementHandlerParams) error

	// Close the decoder, finalizing any state it may contain.
	Close() error

	// Decode the endorsements from the provided []byte.
	// The mediaType parameter allows handlers to distinguish between signed and unsigned CoRIMs.
	// The caCertPool parameter is used for signature verification of signed CoRIMs.
	Decode(data []byte, mediaType string, caCertPool *x509.CertPool) (*EndorsementHandlerResponse, error)
}
