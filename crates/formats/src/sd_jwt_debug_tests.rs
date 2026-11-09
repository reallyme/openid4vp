// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{credential_query, SdJwtPresentationVerificationInput, EXAMPLE_VCT};

#[test]
fn presentation_input_debug_redacts_compact_and_binding_values() {
    let query = credential_query(EXAMPLE_VCT);
    let input = SdJwtPresentationVerificationInput {
        compact: "issuer~disclosure~holder",
        expected_audience: "x509_hash:verifier.example",
        expected_nonce: "secret-nonce",
        now_unix: 1_700_000_001,
        credential_query: &query,
    };
    let debug = format!("{input:?}");

    assert!(!debug.contains(input.compact));
    assert!(!debug.contains(input.expected_audience));
    assert!(!debug.contains(input.expected_nonce));
    assert!(debug.contains("<redacted>"));
}
