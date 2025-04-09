// Copyright 2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package common

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/corim/comid"
	"github.com/veraison/services/handler"
)

// mockExtractor is a mock implementation of IExtractor for testing
type mockExtractor struct {
	Profile string
}

func (m *mockExtractor) RefValExtractor(vt comid.ValueTriples) ([]*handler.Endorsement, error) {
	return []*handler.Endorsement{}, nil
}

func (m *mockExtractor) TaExtractor(kt comid.KeyTriple) (*handler.Endorsement, error) {
	return &handler.Endorsement{}, nil
}

func (m *mockExtractor) SetProfile(profile string) {
	m.Profile = profile
}

func TestSignedCorimDecoder_EmptyData(t *testing.T) {
	// Test with empty data
	extractor := &mockExtractor{}
	caPool := x509.NewCertPool()

	_, err := SignedCorimDecoder([]byte{}, extractor, caPool)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

func TestSignedCorimDecoder_NilCAPool(t *testing.T) {
	// Test with nil CA pool
	extractor := &mockExtractor{}

	_, err := SignedCorimDecoder([]byte{0x01, 0x02, 0x03}, extractor, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil CA certificate pool")
}

func TestSignedCorimDecoder_InvalidData(t *testing.T) {
	// Test with invalid CBOR data
	extractor := &mockExtractor{}
	caPool := x509.NewCertPool()

	_, err := SignedCorimDecoder([]byte("invalid"), extractor, caPool)
	assert.Error(t, err)
}
