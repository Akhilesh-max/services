// Copyright 2023-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsec_cca

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecoder_Decode_OK(t *testing.T) {
	// Skip this test since we don't have the test vectors defined
	t.Skip("Test vectors not defined")

	/*
		tvs := [][]byte{
			// Add proper test vectors when available
		}

		d := &EndorsementHandler{}
		mediaType := "application/corim+cbor"
		var certPool *x509.CertPool = nil

		for _, tv := range tvs {
			_, err := d.Decode(tv, mediaType, certPool)
			assert.NoError(t, err)
		}
	*/
}

func TestDecoder_GetAttestationScheme(t *testing.T) {
	d := &EndorsementHandler{}

	expected := SchemeName

	actual := d.GetAttestationScheme()

	assert.Equal(t, expected, actual)
}

func TestDecoder_GetSupportedMediaTypes(t *testing.T) {
	d := &EndorsementHandler{}

	expected := EndorsementMediaTypes

	actual := d.GetSupportedMediaTypes()

	assert.Equal(t, expected, actual)
}

func TestDecoder_Init(t *testing.T) {
	d := &EndorsementHandler{}

	assert.Nil(t, d.Init(nil))
}

func TestDecoder_Close(t *testing.T) {
	d := &EndorsementHandler{}

	assert.Nil(t, d.Close())
}

func TestDecoder_GetName_ok(t *testing.T) {
	d := &EndorsementHandler{}
	expectedName := "unsigned-corim (Parsec CCA profile)"
	name := d.GetName()
	assert.Equal(t, name, expectedName)
}

func TestDecoder_Decode_empty_data(t *testing.T) {
	d := &EndorsementHandler{}

	emptyData := []byte{}
	mediaType := "application/corim+cbor"
	var certPool *x509.CertPool = nil

	expectedErr := `empty data`

	_, err := d.Decode(emptyData, mediaType, certPool)

	assert.EqualError(t, err, expectedErr)
}

func TestDecoder_Decode_invalid_data(t *testing.T) {
	d := &EndorsementHandler{}

	invalidCbor := []byte("invalid CBOR")
	mediaType := "application/corim+cbor"
	var certPool *x509.CertPool = nil

	expectedErr := `CBOR decoding failed: expected map (CBOR Major Type 5), found Major Type 3`

	_, err := d.Decode(invalidCbor, mediaType, certPool)

	assert.EqualError(t, err, expectedErr)
}
