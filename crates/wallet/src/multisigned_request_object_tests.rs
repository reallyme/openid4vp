// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dc_api::{DcApiErrorReason, JwsJsonGeneral};
use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
};
use serde_json::{json, Map as JsonMap};

use super::{
    verify_multisigned_request_object, MultiSignedRequestObjectSignatureVerifier,
    MAX_MULTISIGNED_REQUEST_OBJECT_BYTES, MAX_MULTISIGNED_REQUEST_OBJECT_SIGNATURES,
};
use crate::{
    VerifiedPlatformOrigin, VerifiedRequestObject, WalletError, WalletErrorReason,
    WalletInvocationContext,
};

fn dc_api_invocation() -> WalletInvocationContext {
    WalletInvocationContext::DigitalCredentialsApi(
        VerifiedPlatformOrigin::from_browser_security_context("https://rp.example".to_owned())
            .expect("test origin is valid"),
    )
}

struct FixtureVerifier;

impl MultiSignedRequestObjectSignatureVerifier for FixtureVerifier {
    fn verify_multisigned_request_object_signature(
        &self,
        compact_jws: &str,
        protected_client_id: &ClientIdentifier,
        _invocation: &crate::WalletInvocationContext,
        _now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        if !compact_jws.ends_with(".valid") {
            return Err(WalletError::new(
                WalletErrorReason::InvalidRequestObjectSignature,
            ));
        }
        Ok(VerifiedRequestObject::new(
            request(protected_client_id.clone()),
            crate::WalletRequestTrustEvidence {
                client_identifier_binding: Some(crate::VerifiedClientIdentifierBinding::new(
                    protected_client_id.clone(),
                    b"test-key",
                )?),
                verifier_attestation: None,
                client_metadata_reference: None,
                x509_certificate_binding: None,
            },
        ))
    }
}

fn request(client_id: ClientIdentifier) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(client_id),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApiJwt),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::MSO_MDOC.to_owned())
                    .expect("test credential format is valid"),
                multiple: false,
                meta: {
                    let mut meta = JsonMap::new();
                    meta.insert(
                        "doctype_value".to_owned(),
                        serde_json::json!("org.iso.18013.5.1.mDL"),
                    );
                    meta
                },
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
        expected_origins: Some(vec!["https://rp.example".to_owned()]),
        iss: Some("client".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(20),
    }
}

fn protected(client_id: &str) -> String {
    reallyme_codec::base64url::bytes_to_base64url(
        serde_json::to_vec(&json!({
            "alg": "ES256",
            "typ": "oauth-authz-req+jwt",
            "client_id": client_id,
        }))
        .expect("test header serializes")
        .as_slice(),
    )
}

fn general_jws(signatures: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "payload": "cGF5bG9hZA",
        "signatures": signatures,
    }))
    .expect("test JWS serializes")
}

fn parse_general_jws(body: &[u8]) -> JwsJsonGeneral {
    JwsJsonGeneral::from_json(body).expect("test JWS JSON is valid")
}

#[test]
fn accepts_when_one_of_multiple_signatures_is_valid() {
    let body = general_jws(json!([
        {
            "protected": protected("decentralized_identifier:did:example:first"),
            "signature": "invalid"
        },
        {
            "protected": protected("decentralized_identifier:did:example:second"),
            "signature": "valid"
        }
    ]));

    let parsed = parse_general_jws(&body);
    verify_multisigned_request_object(&FixtureVerifier, &parsed, &dc_api_invocation(), 11)
        .expect("one independently valid signature accepts the shared request");
}

#[test]
fn rejects_when_every_signature_is_invalid() {
    let body = general_jws(json!([{
        "protected": protected("decentralized_identifier:did:example:verifier"),
        "signature": "invalid"
    }]));

    let parsed = parse_general_jws(&body);
    let error =
        verify_multisigned_request_object(&FixtureVerifier, &parsed, &dc_api_invocation(), 11)
            .expect_err("all invalid signatures must reject the request");

    assert_eq!(
        error.reason(),
        WalletErrorReason::InvalidRequestObjectSignature
    );
}

#[test]
fn rejects_duplicate_general_jws_members() {
    let body = br#"{"payload":"cGF5bG9hZA","payload":"cGF5bG9hZA","signatures":[]}"#;

    let error =
        JwsJsonGeneral::from_json(body).expect_err("duplicate security members must be rejected");

    assert_eq!(error.reason(), DcApiErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_missing_protected_client_identifier() {
    let header = reallyme_codec::base64url::bytes_to_base64url(br#"{"alg":"ES256"}"#);
    let body = general_jws(json!([{"protected": header, "signature": "valid"}]));

    let parsed = parse_general_jws(&body);
    let error =
        verify_multisigned_request_object(&FixtureVerifier, &parsed, &dc_api_invocation(), 11)
            .expect_err("every signature must bind its own client identifier");

    assert_eq!(
        error.reason(),
        WalletErrorReason::InvalidRequestObjectSignature
    );
}

#[test]
fn rejects_excessive_signature_count() {
    let signature = json!({
        "protected": protected("decentralized_identifier:did:example:verifier"),
        "signature": "valid"
    });
    let body = general_jws(json!(vec![
        signature;
        MAX_MULTISIGNED_REQUEST_OBJECT_SIGNATURES + 1
    ]));

    let error = JwsJsonGeneral::from_json(&body)
        .expect_err("signature count is bounded before verification");

    assert_eq!(
        error.reason(),
        DcApiErrorReason::TooManyRequestObjectSignatures
    );
}

#[test]
fn rejects_oversized_general_jws_before_parsing() {
    let body = vec![b' '; MAX_MULTISIGNED_REQUEST_OBJECT_BYTES + 1];

    let error = JwsJsonGeneral::from_json(&body)
        .expect_err("oversized input must be rejected before parsing");

    assert_eq!(error.reason(), DcApiErrorReason::RequestObjectTooLarge);
}
