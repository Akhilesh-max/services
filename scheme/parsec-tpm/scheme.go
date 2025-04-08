// Copyright 2023-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package parsec_tpm

const (
	SchemeName         = "PARSEC_TPM"
	EndorsementProfile = `"tag:github.com/parallaxsecond,2023-03-03:tpm"`
)

var EndorsementMediaTypes = []string{
	// Unsigned CoRIM profiles
	`application/corim-unsigned+cbor; profile="http://veraison.example/parsec/tpm/1"`,
	// Signed CoRIM profiles
	`application/corim-signed+cbor; profile="http://veraison.example/parsec/tpm/1"`,
}

var EvidenceMediaTypes = []string{
	"application/vnd.veraison.parsec-tpm-evidence",
}
