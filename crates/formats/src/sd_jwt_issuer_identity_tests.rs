// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{credential_query, presentation, provider, test_key, EXAMPLE_VCT};
use crate::sd_jwt::{
    verify_sd_jwt_presentation, SdJwtFormatErrorReason, SdJwtPresentationVerificationInput,
};

#[test]
fn rejects_cross_issuer_key_substitution() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation(&issuer, &holder, "nonce-123");
    let mut provider = provider(&issuer, &holder, Ok(()));
    provider.issuer_identity = "https://other-issuer.example".to_owned();
    let query = credential_query(EXAMPLE_VCT);

    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("a trusted key for a different issuer must not authorize the credential");

    assert_eq!(
        error.reason(),
        SdJwtFormatErrorReason::IssuerIdentityMismatch
    );
}
