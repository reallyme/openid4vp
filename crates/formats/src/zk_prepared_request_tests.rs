// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(
    clippy::expect_used,
    reason = "test fixtures and assertions fail on unexpected values"
)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, QueryId};
use reallyme_openid4vp_types::ResponseMode;
use serde_json::json;

use super::{derive_prepared_openid4vp_request_hashes, PreparedOpenId4VpRequestInput};

fn query() -> CredentialQuery {
    CredentialQuery {
        id: QueryId::parse("age").expect("test query id"),
        format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
            .expect("test format"),
        multiple: false,
        meta: json!({
            "profile": "persona_credential_evidence_public_persona_v1",
            "hash_strategy": "sha256",
            "claim_name_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "claim_value_b64u": "dHJ1ZQ"
        })
        .as_object()
        .expect("test metadata object")
        .clone(),
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    }
}

fn input<'a>(query: &'a CredentialQuery) -> PreparedOpenId4VpRequestInput<'a> {
    PreparedOpenId4VpRequestInput {
        nonce: "one-time-challenge",
        audience: "x509_san_dns:verifier.example",
        query,
        transaction_hashes: &[],
        response_mode: ResponseMode::DirectPostJwt,
        response_uri: Some("https://verifier.example/response"),
        redirect_uri: None,
        state: Some("state-1"),
        issued_at_unix: 100,
        expires_at_unix: 200,
    }
}

#[test]
fn request_projection_binds_query_policy_session_and_transport() {
    let base_query = query();
    let base = derive_prepared_openid4vp_request_hashes(input(&base_query))
        .expect("valid signed request projection");
    let repeated = derive_prepared_openid4vp_request_hashes(input(&base_query))
        .expect("same retained session projection");
    assert_eq!(base.nonce, repeated.nonce);
    assert_eq!(
        base.requested_claims_sha256,
        repeated.requested_claims_sha256
    );
    assert_eq!(
        base.transport_context_sha256,
        repeated.transport_context_sha256
    );

    let mut changed = input(&base_query);
    changed.nonce = "different-challenge";
    assert_ne!(
        base.nonce,
        derive_prepared_openid4vp_request_hashes(changed)
            .expect("changed nonce remains valid")
            .nonce
    );
    let mut changed = input(&base_query);
    changed.audience = "origin:https://verifier.example";
    assert_ne!(
        base.audience_sha256,
        derive_prepared_openid4vp_request_hashes(changed)
            .expect("changed audience remains valid")
            .audience_sha256
    );
    let mut changed_query = query();
    changed_query
        .meta
        .insert("claim_value_b64u".to_owned(), json!("ZmFsc2U"));
    let changed = derive_prepared_openid4vp_request_hashes(input(&changed_query))
        .expect("changed policy remains valid");
    assert_ne!(
        base.requested_claims_sha256,
        changed.requested_claims_sha256
    );
    assert_ne!(base.verifier_policy_sha256, changed.verifier_policy_sha256);

    let hashes = [[7_u8; 32], [8_u8; 32]];
    let mut changed = input(&base_query);
    changed.transaction_hashes = &hashes;
    assert_ne!(
        base.transaction_data_sha256,
        derive_prepared_openid4vp_request_hashes(changed)
            .expect("ordered transaction hashes remain valid")
            .transaction_data_sha256
    );
    let mut changed = input(&base_query);
    changed.response_uri = Some("https://verifier.example/other");
    assert_ne!(
        base.transport_context_sha256,
        derive_prepared_openid4vp_request_hashes(changed)
            .expect("changed destination remains valid")
            .transport_context_sha256
    );
}

#[test]
fn request_projection_checks_response_mode_endpoints_and_time() {
    let query = query();
    let mut dc_api = input(&query);
    dc_api.response_mode = ResponseMode::DcApiJwt;
    dc_api.response_uri = None;
    assert!(derive_prepared_openid4vp_request_hashes(dc_api).is_ok());

    let mut wrong_endpoint = input(&query);
    wrong_endpoint.response_mode = ResponseMode::DcApi;
    assert!(derive_prepared_openid4vp_request_hashes(wrong_endpoint).is_err());

    let mut wrong_interval = input(&query);
    wrong_interval.expires_at_unix = wrong_interval.issued_at_unix;
    assert!(derive_prepared_openid4vp_request_hashes(wrong_interval).is_err());
}
