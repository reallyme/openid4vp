// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
};
use serde_json::{json, Map as JsonMap};

use crate::request::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialGetRequestData,
    DigitalCredentialRequestOptions, JwsJsonGeneral, JwsJsonSignature, MAX_JWS_JSON_SIGNATURES,
};
use crate::DcApiErrorReason;

fn request(response_mode: ResponseMode) -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(response_mode),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::MSO_MDOC.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta: {
                    let mut meta = JsonMap::new();
                    meta.insert("doctype_value".to_owned(), json!("org.iso.18013.5.1.mDL"));
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
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    }
}

#[test]
fn accepts_unsigned_dc_api_request_without_client_id() {
    let request = request(ResponseMode::DcApi);

    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("unsigned DC API request is valid");

    assert_eq!(entry.protocol, "openid4vp-v1-unsigned");
}

#[test]
fn normalizes_ignored_unsigned_dc_api_identity_members() {
    let mut request = request(ResponseMode::DcApi);
    request.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:verifier.example").expect("test client id is valid"),
    );
    request.expected_origins = Some(vec!["https://wrong.example".to_owned()]);

    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("unsigned DC API identity members are ignored");

    assert!(matches!(
        &entry.data,
        DigitalCredentialGetRequestData::Unsigned(_)
    ));
    if let DigitalCredentialGetRequestData::Unsigned(normalized) = &entry.data {
        assert!(normalized.client_id.is_none());
        assert!(normalized.expected_origins.is_none());
    }
}

#[test]
fn deserializes_unsigned_dc_api_request_while_ignoring_invalid_identity_members() {
    let mut value = serde_json::to_value(request(ResponseMode::DcApi))
        .expect("test request serializes to JSON");
    value["client_id"] = json!("unknown-prefix:must-be-ignored");
    value["expected_origins"] = json!(["https://wrong.example"]);
    value["unknown_parameter"] = json!("ignored");
    let entry_json = json!({
        "protocol": "openid4vp-v1-unsigned",
        "data": value,
    });

    let entry: DigitalCredentialGetRequest =
        serde_json::from_value(entry_json).expect("ignored members must not block unsigned DC API");

    assert!(matches!(
        &entry.data,
        DigitalCredentialGetRequestData::Unsigned(_)
    ));
    if let DigitalCredentialGetRequestData::Unsigned(normalized) = &entry.data {
        assert!(normalized.client_id.is_none());
        assert!(normalized.expected_origins.is_none());
    }
}

#[test]
fn rejects_protocol_and_request_data_mismatch_during_deserialization() {
    let entry_json = json!({
        "protocol": "openid4vp-v1-signed",
        "data": serde_json::to_value(request(ResponseMode::DcApi))
            .expect("test request serializes"),
    });

    serde_json::from_value::<DigitalCredentialGetRequest>(entry_json)
        .expect_err("protocol/data mismatch must fail closed");
}

#[test]
fn accepts_unsigned_dc_api_request_with_encrypted_response_mode() {
    let request = request(ResponseMode::DcApiJwt);

    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("unsigned DC API request may request encrypted response");

    assert_eq!(entry.protocol, "openid4vp-v1-unsigned");
}

#[test]
fn accepts_signed_dc_api_request_object_data_shape() {
    let entry = DigitalCredentialGetRequest::new_signed_request_object(
        DcApiProtocol::v1(DcApiRequestKind::Signed),
        "header.payload.signature".to_owned(),
    )
    .expect("signed DC API request object is valid");
    let value = serde_json::to_value(&entry).expect("DC API request serializes");

    assert_eq!(entry.protocol, "openid4vp-v1-signed");
    assert_eq!(value["data"]["request"], "header.payload.signature");
}

#[test]
fn rejects_expanded_data_for_signed_dc_api_request() {
    let err = DigitalCredentialGetRequest::new(
        DcApiProtocol::v1(DcApiRequestKind::Signed),
        request(ResponseMode::DcApiJwt),
    )
    .expect_err("signed DC API request uses data.request");

    assert_eq!(err.reason(), DcApiErrorReason::InvalidProtocol);
}

#[test]
fn rejects_unsupported_protocol_version() {
    let err = DigitalCredentialGetRequest::new(
        DcApiProtocol {
            version: 2,
            kind: DcApiRequestKind::Unsigned,
        },
        request(ResponseMode::DcApi),
    )
    .expect_err("only v1 protocol identifiers are supported");

    assert_eq!(err.reason(), DcApiErrorReason::InvalidProtocol);
}

#[test]
fn rejects_empty_request_options() {
    let err = DigitalCredentialRequestOptions::new(Vec::new())
        .expect_err("browser request set must be non-empty");

    assert_eq!(err.reason(), DcApiErrorReason::EmptyRequestSet);
}

#[test]
fn accepts_multisigned_dc_api_request_object_data_shape() {
    let signature = JwsJsonSignature::new("cHJvdGVjdGVk".to_owned(), "c2lnbmF0dXJl".to_owned())
        .expect("test signature is valid");
    let request = JwsJsonGeneral::new("cGF5bG9hZA".to_owned(), vec![signature])
        .expect("test JWS JSON is valid");
    let entry = DigitalCredentialGetRequest::new_multisigned_request_object(
        DcApiProtocol::v1(DcApiRequestKind::Multisigned),
        request,
    )
    .expect("multi-signed DC API request object is valid");
    let value = serde_json::to_value(&entry).expect("DC API request serializes");

    assert_eq!(entry.protocol, "openid4vp-v1-multisigned");
    assert_eq!(value["data"]["request"]["payload"], "cGF5bG9hZA");
    assert_eq!(
        value["data"]["request"]["signatures"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn parses_bounded_multisigned_jws_and_rejects_duplicate_members() {
    let parsed = JwsJsonGeneral::from_json(
        br#"{"payload":"cGF5bG9hZA","signatures":[{"protected":"cHJvdGVjdGVk","signature":"c2lnbmF0dXJl"}]}"#,
    )
    .expect("valid JWS JSON parses");
    assert_eq!(parsed.signatures.len(), 1);

    let error = JwsJsonGeneral::from_json(
        br#"{"payload":"cGF5bG9hZA","payload":"cGF5bG9hZA","signatures":[]}"#,
    )
    .expect_err("duplicate security members are rejected");
    assert_eq!(error.reason(), DcApiErrorReason::InvalidRequestObject);
}

#[test]
fn rejects_invalid_or_excessive_multisigned_jws_signatures() {
    let invalid = JwsJsonSignature::new("not+base64url".to_owned(), "valid".to_owned())
        .expect_err("invalid protected encoding is rejected");
    assert_eq!(invalid.reason(), DcApiErrorReason::InvalidRequestObject);

    let signatures = (0..=MAX_JWS_JSON_SIGNATURES)
        .map(|_| {
            JwsJsonSignature::new("cHJvdGVjdGVk".to_owned(), "c2lnbmF0dXJl".to_owned())
                .expect("test signature is valid")
        })
        .collect();
    let error = JwsJsonGeneral::new("cGF5bG9hZA".to_owned(), signatures)
        .expect_err("signature count is bounded");
    assert_eq!(
        error.reason(),
        DcApiErrorReason::TooManyRequestObjectSignatures
    );
}

#[test]
fn sensitive_dc_api_request_debug_output_is_redacted() {
    let signature = JwsJsonSignature::new("cHJvdGVjdGVk".to_owned(), "c2lnbmF0dXJl".to_owned())
        .expect("test signature is valid");
    let request = JwsJsonGeneral::new("cGF5bG9hZA".to_owned(), vec![signature])
        .expect("test JWS JSON is valid");
    let entry = DigitalCredentialGetRequest::new_multisigned_request_object(
        DcApiProtocol::v1(DcApiRequestKind::Multisigned),
        request,
    )
    .expect("multi-signed DC API request object is valid");
    let debug = format!("{entry:?}");

    assert!(!debug.contains("cGF5bG9hZA"));
    assert!(!debug.contains("cHJvdGVjdGVk"));
    assert!(!debug.contains("c2lnbmF0dXJl"));
}
