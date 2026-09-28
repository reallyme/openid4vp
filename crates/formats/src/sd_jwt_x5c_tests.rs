// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;
use reallyme_sd_jwt::{build_key_binding_jwt, serialize_sd_jwt_compact, KeyBindingJwtBuildOptions};
use serde_json::json;

use super::{credential_query, presentation, provider, test_key, TestKey, EXAMPLE_VCT};
use crate::sd_jwt::{
    verify_sd_jwt_presentation, SdJwtFormatErrorReason, SdJwtIssuerKeySource,
    SdJwtPresentationVerificationInput,
};

#[test]
fn accepts_only_trust_authenticated_x5c_issuer_headers() {
    let issuer = test_key();
    let holder = test_key();
    let compact = presentation_with_x5c(&issuer, &holder, "nonce-123");
    let query = credential_query(EXAMPLE_VCT);
    let mut provider = provider(&issuer, &holder, Ok(()));

    let rejected = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("an x5c header without correlated trust evidence is rejected");
    assert_eq!(
        rejected.reason(),
        SdJwtFormatErrorReason::InvalidCredentialSignature
    );

    provider.issuer_key_source = SdJwtIssuerKeySource::AuthenticatedX509Header;
    verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect("an authenticated x5c leaf remains bound to the supplied issuer key");

    let without_x5c = presentation(&issuer, &holder, "nonce-123");
    let error = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &without_x5c,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect_err("x5c trust evidence cannot authorize a JWT without an x5c path");
    assert_eq!(
        error.reason(),
        SdJwtFormatErrorReason::InvalidCredentialSignature
    );
}

fn presentation_with_x5c(issuer: &TestKey, holder: &TestKey, nonce: &str) -> String {
    let issuer_payload = json!({
        "iss": "https://issuer.example",
        "vct": EXAMPLE_VCT,
        "_sd_alg": "sha-256",
        "cnf": { "jwk": holder.jwk.clone() },
        "iat": 1_700_000_000_u64
    });
    let header = bytes_to_base64url(br#"{"alg":"EdDSA","typ":"dc+sd-jwt","x5c":["AQ=="]}"#);
    let payload = bytes_to_base64url(
        &serde_json::to_vec(&issuer_payload).expect("issuer payload serializes"),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign(
        Algorithm::Ed25519,
        &issuer.private,
        signing_input.as_bytes(),
    )
    .expect("issuer JWT signs");
    let issuer_signed_jwt = format!("{signing_input}.{}", bytes_to_base64url(&signature));
    let disclosures = Vec::new();
    let key_binding_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &disclosures,
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "x509_hash:verifier.example",
            nonce,
            issued_at_unix: 1_700_000_000,
        },
    )
    .expect("key binding JWT signs");
    let compact_without_key_binding =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures).expect("SD-JWT serializes");
    format!("{compact_without_key_binding}{key_binding_jwt}")
}
