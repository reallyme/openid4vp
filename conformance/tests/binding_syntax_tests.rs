// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

//! Section 5.2 binding syntax across wallet and verifier request boundaries.

use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_verifier::{validate_jar_claims, JarPolicy, VerifierErrorReason};
use reallyme_openid4vp_wallet::{
    validate_unsigned_dc_api_request, validate_wallet_request_object, WalletAuthorizationRequest,
    WalletErrorReason,
};
use serde_json::json;

const VALID_BINDING: &str = "Ab0123456789-._~xyz";
const INVALID_BINDINGS: [&str; 8] = [
    "0123456789abcdef ",
    "0123456789abcdef+",
    "0123456789abcdef%20",
    "0123456789abcdef/",
    "0123456789abcdef=",
    "0123456789abcdef\n",
    "0123456789abcdefé",
    "0123456789abcdef\0",
];

fn request() -> AuthorizationRequestObject {
    serde_json::from_value(json!({
        "client_id":"decentralized_identifier:did:example:verifier",
        "iss":"decentralized_identifier:did:example:verifier", "aud":["wallet"],
        "iat":10, "exp":100, "response_type":"vp_token", "response_mode":"dc_api",
        "nonce":VALID_BINDING, "state":VALID_BINDING, "expected_origins":["https://rp.example"],
        "dcql_query":{"credentials":[{"id":"pid", "format":"dc+sd-jwt",
            "meta":{"vct_values":["urn:example:pid"]}}]}
    }))
    .expect("valid request fixture")
}

#[test]
fn accepts_every_url_safe_binding_character_without_normalization() {
    let request = request();
    validate_wallet_request_object(&request, Some("https://rp.example"), 11)
        .expect("URL-safe signed request binding");
    validate_jar_claims(&request, 11, JarPolicy::default()).expect("URL-safe signing binding");
    let unsigned = validate_unsigned_dc_api_request(&request).expect("URL-safe unsigned nonce");
    assert_eq!(unsigned.request().nonce, VALID_BINDING);
}

#[test]
fn rejects_non_url_safe_nonce_at_wallet_and_verifier_boundaries() {
    for invalid in INVALID_BINDINGS {
        let mut request = request();
        request.nonce = invalid.to_owned();
        assert_eq!(
            validate_wallet_request_object(&request, Some("https://rp.example"), 11)
                .map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidRequestObject)
        );
        assert!(validate_unsigned_dc_api_request(&request).is_err());
        assert_eq!(
            validate_jar_claims(&request, 11, JarPolicy::default()).map_err(|error| error.reason()),
            Err(VerifierErrorReason::InvalidBinding)
        );
    }
}

#[test]
fn rejects_non_url_safe_signed_state_but_ignores_unsigned_dc_api_state() {
    for invalid in INVALID_BINDINGS {
        let mut request = request();
        request.state = Some(invalid.to_owned());
        request.response_mode = Some(reallyme_openid4vp_types::ResponseMode::DirectPost);
        request.response_uri = Some("https://rp.example/response".to_owned());
        request.expected_origins = None;
        assert!(validate_wallet_request_object(&request, None, 11).is_err());
        assert_eq!(
            validate_jar_claims(&request, 11, JarPolicy::default()).map_err(|error| error.reason()),
            Err(VerifierErrorReason::InvalidBinding)
        );
        request.response_mode = Some(reallyme_openid4vp_types::ResponseMode::DcApi);
        request.response_uri = None;
        let unsigned = validate_unsigned_dc_api_request(&request)
            .expect("state is not a DC API request parameter");
        assert!(unsigned.request().state.is_none());
    }
}
