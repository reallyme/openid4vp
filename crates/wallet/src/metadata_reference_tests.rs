// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientMetadata, ResponseType,
};
use serde_json::{Map as JsonMap, Value as JsonValue};

use crate::metadata_reference::{
    validate_client_metadata_reference_binding, VerifiedClientMetadataReference,
};
use crate::WalletErrorReason;

fn metadata() -> ClientMetadata {
    ClientMetadata {
        raw: JsonValue::Object(JsonMap::new()),
    }
}

fn request() -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: None,
        response_uri: None,
        redirect_uri: Some("https://verifier.example/cb".to_owned()),
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
        client_metadata_uri: Some("https://verifier.example/metadata.json".to_owned()),
        expected_origins: None,
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(20),
    }
}

#[test]
fn accepts_fresh_matching_metadata_reference() {
    let evidence = VerifiedClientMetadataReference::new(
        "https://verifier.example/metadata.json".to_owned(),
        metadata(),
        20,
    )
    .expect("test evidence is valid");

    validate_client_metadata_reference_binding(&request(), Some(&evidence), 10)
        .expect("fresh metadata evidence is accepted");
}

#[test]
fn rejects_metadata_reference_without_verified_evidence() {
    let err = validate_client_metadata_reference_binding(&request(), None, 10)
        .expect_err("metadata reference requires verified evidence");

    assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
}

#[test]
fn rejects_stale_metadata_reference_evidence() {
    let evidence = VerifiedClientMetadataReference::new(
        "https://verifier.example/metadata.json".to_owned(),
        metadata(),
        10,
    )
    .expect("test evidence is valid");

    let err = validate_client_metadata_reference_binding(&request(), Some(&evidence), 10)
        .expect_err("stale metadata evidence is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
}

#[test]
fn rejects_conflicting_inline_and_referenced_metadata() {
    let mut request = request();
    request.client_metadata = Some(metadata());
    let evidence = VerifiedClientMetadataReference::new(
        "https://verifier.example/metadata.json".to_owned(),
        metadata(),
        20,
    )
    .expect("test evidence is valid");

    let err = validate_client_metadata_reference_binding(&request, Some(&evidence), 10)
        .expect_err("ambiguous metadata source is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidMetadataReference);
}
