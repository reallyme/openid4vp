// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_jose::jwt::{encode_signed_jwt_with_header_options, JwtHeaderEncodeOptions};
use reallyme_sd_jwt::{build_key_binding_jwt, serialize_sd_jwt_compact, KeyBindingJwtBuildOptions};
use serde_json::{json, Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};

use super::{
    credential_query, provider, test_key, verify_sd_jwt_presentation,
    SdJwtPresentationVerificationInput, EXAMPLE_VCT,
};

#[test]
fn verified_projection_excludes_an_undisclosed_claim() {
    let issuer = test_key();
    let holder = test_key();
    let undisclosed = bytes_to_base64url(br#"["audit-salt","family_name","Sensitive"]"#);
    let undisclosed_digest = bytes_to_base64url(&Sha256::digest(undisclosed.as_bytes()));
    let mut issuer_payload = JsonMap::new();
    issuer_payload.insert("iss".to_owned(), json!("https://issuer.example"));
    issuer_payload.insert("vct".to_owned(), json!(EXAMPLE_VCT));
    issuer_payload.insert("_sd_alg".to_owned(), json!("sha-256"));
    issuer_payload.insert("_sd".to_owned(), json!([undisclosed_digest]));
    issuer_payload.insert("given_name".to_owned(), json!("Visible"));
    issuer_payload.insert("cnf".to_owned(), json!({ "jwk": holder.jwk.clone() }));
    let issuer_signed_jwt = encode_signed_jwt_with_header_options(
        &JsonValue::Object(issuer_payload),
        &issuer.jwk,
        &issuer.private,
        &JwtHeaderEncodeOptions::new(Some("dc+sd-jwt".to_owned())),
    )
    .expect("issuer JWT signs");
    let disclosures = Vec::new();
    let key_binding_jwt = build_key_binding_jwt(
        &issuer_signed_jwt,
        &disclosures,
        &KeyBindingJwtBuildOptions {
            holder_jwk: &holder.jwk,
            holder_private_key: &holder.private,
            audience: "x509_hash:verifier.example",
            nonce: "nonce-123",
            issued_at_unix: 1_700_000_000,
        },
    )
    .expect("key binding JWT signs");
    let compact_without_key_binding =
        serialize_sd_jwt_compact(&issuer_signed_jwt, &disclosures).expect("SD-JWT serializes");
    let compact = format!("{compact_without_key_binding}{key_binding_jwt}");
    let provider = provider(&issuer, &holder, Ok(()));
    let query = credential_query(EXAMPLE_VCT);

    let verified = verify_sd_jwt_presentation(
        SdJwtPresentationVerificationInput {
            compact: &compact,
            expected_audience: "x509_hash:verifier.example",
            expected_nonce: "nonce-123",
            now_unix: 1_700_000_001,
            credential_query: &query,
        },
        &provider,
    )
    .expect("presentation with an omitted optional disclosure verifies");

    assert_eq!(
        verified.resolved_payload.get("given_name"),
        Some(&json!("Visible"))
    );
    assert!(verified.resolved_payload.get("family_name").is_none());
    assert!(!verified.resolved_payload.to_string().contains("Sensitive"));
}
