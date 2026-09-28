// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier, ResponseType};
use reallyme_openid4vp_verifier::{validate_jar_claims, VerifierErrorReason};
use reallyme_openid4vp_wallet::{parse_authorization_request_transport, WalletErrorReason};

use crate::policy::{
    OpenId4VpRequestPolicy, DEFAULT_MAX_REQUEST_JWT_BYTES, DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS,
};

#[test]
fn production_policy_maps_to_lower_crate_policies() {
    let policy = OpenId4VpRequestPolicy::production();

    let wallet_policy = policy.wallet_transport_policy();
    assert_eq!(
        wallet_policy.max_request_jwt_bytes,
        DEFAULT_MAX_REQUEST_JWT_BYTES
    );
    assert!(wallet_policy.require_signed_request_object);
    let jar_policy = policy.jar_policy();
    assert!(jar_policy.require_issuer);
    assert!(jar_policy.require_issuer_matches_client_id);
    assert!(jar_policy.require_audience);
    assert!(jar_policy.require_issued_at);
    assert!(jar_policy.require_expiration);
    assert_eq!(
        jar_policy.max_lifetime_secs,
        Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS)
    );

    #[cfg(feature = "http")]
    {
        let request_uri_policy = policy.request_uri_resolution_policy();
        assert_eq!(
            request_uri_policy.max_request_jwt_bytes,
            DEFAULT_MAX_REQUEST_JWT_BYTES
        );
    }
}

#[test]
fn non_default_request_policy_is_enforced_at_wallet_and_verifier_boundaries() {
    let policy = OpenId4VpRequestPolicy {
        max_request_jwt_bytes: 4,
        max_authorization_request_bytes: 32,
        max_authorization_request_parameters: 1,
        require_signed_request_object: true,
        require_request_object_issuer: true,
        require_issuer_matches_client_id: true,
        require_request_object_audience: true,
        require_request_object_issued_at: true,
        require_request_object_expiration: true,
        max_request_object_lifetime_secs: Some(5),
        issued_at_future_skew_secs: 2,
    };

    let size_error = parse_authorization_request_transport(
        "request=header.payload.signature",
        policy.wallet_transport_policy(),
    )
    .expect_err("the facade's non-default JWT size reaches wallet parsing");
    assert_eq!(
        size_error.reason(),
        WalletErrorReason::RequestObjectTooLarge
    );

    let lifetime_error = validate_jar_claims(&request(20, 10), 10, policy.jar_policy())
        .expect_err("the facade's non-default lifetime reaches verifier validation");
    assert_eq!(
        lifetime_error.reason(),
        VerifierErrorReason::RequestObjectLifetimeTooLong
    );

    let future_iat_error = validate_jar_claims(&request(16, 13), 10, policy.jar_policy())
        .expect_err("the facade's non-default clock skew reaches verifier validation");
    assert_eq!(
        future_iat_error.reason(),
        VerifierErrorReason::RequestObjectIssuedInFuture
    );

    #[cfg(feature = "http")]
    assert_eq!(
        policy.request_uri_resolution_policy().max_request_jwt_bytes,
        4
    );
}

fn request(expiration_unix: u64, issued_at_unix: u64) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client identifier is valid"),
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
                id: QueryId::parse("pid").expect("test query identifier is valid"),
                format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                    .expect("test credential format is valid"),
                multiple: false,
                meta: Default::default(),
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
        iat: Some(issued_at_unix),
        exp: Some(expiration_unix),
    }
}
