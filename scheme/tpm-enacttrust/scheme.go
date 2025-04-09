// Copyright 2023-2024 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tpm_enacttrust

const SchemeName = "TPM_ENACTTRUST"

var (
	EndorsementMediaTypes = []string{
		// Unsigned CoRIMs
		`application/corim-unsigned+cbor; profile="http://enacttrust.com/veraison/1.0.0"`,
		// Signed CoRIMs
		`application/corim-signed+cbor; profile="http://enacttrust.com/veraison/1.0.0"`,
	}

	EvidenceMediaTypes = []string{
		"application/vnd.enacttrust.tpm-evidence",
	}
)
