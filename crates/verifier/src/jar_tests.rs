// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier, ResponseType};
use serde_json::Map as JsonMap;
use zeroize::Zeroize;

use crate::jar::{
    validate_jar_claims, CompactJwt, JarPolicy, MAX_COMPACT_REQUEST_OBJECT_JWT_BYTES,
};
use crate::VerifierErrorReason;

fn request(exp: u64, iat: u64) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: None,
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta: JsonMap::new(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(iat),
        exp: Some(exp),
    }
}

#[test]
fn compact_jwt_rejects_malformed_request_object() {
    let err = CompactJwt::new("header.payload".to_owned())
        .expect_err("signed Request Object must be compact JWS");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestObject);
}

#[test]
fn compact_jwt_rejects_encrypted_request_object() {
    let err = CompactJwt::new("eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn".to_owned())
        .expect_err("signer output must be compact JWS, not JWE");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestObject);
}

#[test]
fn compact_jwt_rejects_oversized_request_object() {
    let err = CompactJwt::new("a".repeat(MAX_COMPACT_REQUEST_OBJECT_JWT_BYTES + 1))
        .expect_err("oversized Request Object must fail before parsing");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestObject);
}

#[test]
fn redacts_and_zeroizes_compact_request_object_jwt() {
    let mut jwt =
        CompactJwt::new("c2lnbmVk.cmVxdWVzdA.and0".to_owned()).expect("test compact JWS is valid");

    let debug = format!("{jwt:?}");
    assert!(!debug.contains("c2lnbmVk"));
    assert!(debug.contains("<redacted>"));

    jwt.zeroize();
    assert!(jwt.as_str().is_empty());
}

#[test]
fn rejects_expired_request_object() {
    let err = validate_jar_claims(&request(10, 1), 11, JarPolicy::default())
        .expect_err("expired request object is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::RequestObjectExpired);
}

#[test]
fn rejects_zero_clock_for_temporal_validation() {
    let err = validate_jar_claims(&request(20, 10), 0, JarPolicy::default())
        .expect_err("zero clock is not a temporal validation bypass");

    assert_eq!(err.reason(), VerifierErrorReason::ClockUnavailable);
}

#[test]
fn rejects_issuer_client_id_mismatch() {
    let mut request = request(20, 10);
    request.iss = Some("x509_san_dns:other.example".to_owned());

    let err = validate_jar_claims(&request, 11, JarPolicy::default())
        .expect_err("issuer must match client_id");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::IssuerClientIdentifierMismatch
    );
}

#[test]
fn rejects_missing_audience() {
    let mut request = request(20, 10);
    request.aud = None;

    let err = validate_jar_claims(&request, 11, JarPolicy::default())
        .expect_err("audience is required by default policy");

    assert_eq!(err.reason(), VerifierErrorReason::MissingAudience);
}

#[test]
fn rejects_missing_client_identifier() {
    let mut request = request(20, 10);
    request.client_id = None;

    let err =
        validate_jar_claims(&request, 11, JarPolicy::default()).expect_err("client_id is required");

    assert_eq!(err.reason(), VerifierErrorReason::MissingClientIdentifier);
}

#[test]
fn rejects_missing_nonce() {
    let mut request = request(20, 10);
    request.nonce.clear();

    let err = validate_jar_claims(&request, 11, JarPolicy::default())
        .expect_err("nonce is required for holder binding");

    assert_eq!(err.reason(), VerifierErrorReason::MissingNonce);
}

#[test]
fn rejects_short_nonce_and_state() {
    let mut short_nonce = request(20, 10);
    short_nonce.nonce = "1".to_owned();
    let nonce_error = validate_jar_claims(&short_nonce, 11, JarPolicy::default())
        .expect_err("short nonce must fail closed");
    assert_eq!(nonce_error.reason(), VerifierErrorReason::MissingNonce);

    let mut short_state = request(20, 10);
    short_state.state = Some("1".to_owned());
    let state_error = validate_jar_claims(&short_state, 11, JarPolicy::default())
        .expect_err("short state must fail closed");
    assert_eq!(state_error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn rejects_missing_issued_at() {
    let mut request = request(20, 10);
    request.iat = None;

    let err = validate_jar_claims(&request, 11, JarPolicy::default())
        .expect_err("iat is required by default policy");

    assert_eq!(err.reason(), VerifierErrorReason::MissingIssuedAt);
}

#[test]
fn rejects_issued_at_too_far_in_future() {
    let mut request = request(120, 100);

    let err = validate_jar_claims(&request, 11, JarPolicy::default())
        .expect_err("future iat beyond skew is rejected");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::RequestObjectIssuedInFuture
    );

    request.iat = Some(71);
    validate_jar_claims(&request, 11, JarPolicy::default())
        .expect("iat within default skew is accepted");
}

#[test]
fn rejects_expiration_before_issued_at() {
    let err = validate_jar_claims(&request(20, 30), 11, JarPolicy::default())
        .expect_err("exp before iat is rejected");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::RequestObjectIssuedInFuture
    );
}

#[test]
fn rejects_lifetime_longer_than_policy() {
    let err = validate_jar_claims(&request(400, 10), 11, JarPolicy::default())
        .expect_err("request object lifetime is bounded");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::RequestObjectLifetimeTooLong
    );
}
