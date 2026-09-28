// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifier, ResponseType};
use serde_json::Map as JsonMap;

use crate::verifier_attestation::{
    validate_verifier_attestation_binding, VerifiedVerifierAttestation,
};
use crate::WalletErrorReason;

fn attestation(
    subject: String,
    redirect_uris: Option<Vec<String>>,
) -> Result<VerifiedVerifierAttestation, crate::WalletError> {
    VerifiedVerifierAttestation::new(subject, redirect_uris, vec![1_u8], 100)
}

fn request() -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("verifier_attestation:verifier.example")
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
        client_metadata_uri: None,
        expected_origins: None,
        iss: Some("verifier_attestation:verifier.example".to_owned()),
        aud: Some(vec!["wallet".to_owned()]),
        iat: Some(10),
        exp: Some(20),
    }
}

#[test]
fn accepts_matching_verifier_attestation_binding() {
    let attestation = attestation(
        "verifier.example".to_owned(),
        Some(vec!["https://verifier.example/cb".to_owned()]),
    )
    .expect("test attestation is valid");

    validate_verifier_attestation_binding(&request(), &attestation, &[1_u8], 99)
        .expect("matching attestation is valid");
}

#[test]
fn rejects_verifier_attestation_subject_mismatch() {
    let attestation =
        attestation("other.example".to_owned(), None).expect("test attestation is valid");

    let err = validate_verifier_attestation_binding(&request(), &attestation, &[1_u8], 99)
        .expect_err("subject mismatch is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_verifier_attestation_redirect_uri_mismatch() {
    let attestation = attestation(
        "verifier.example".to_owned(),
        Some(vec!["https://verifier.example/other".to_owned()]),
    )
    .expect("test attestation is valid");

    let err = validate_verifier_attestation_binding(&request(), &attestation, &[1_u8], 99)
        .expect_err("redirect_uri mismatch is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_empty_verifier_attestation_subject() {
    let err = attestation(String::new(), None).expect_err("empty attestation subject is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_empty_verifier_attestation_redirect_uri_list() {
    let err = attestation("verifier.example".to_owned(), Some(vec![]))
        .expect_err("empty redirect_uri list is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_empty_verifier_attestation_redirect_uri_value() {
    let err = attestation("verifier.example".to_owned(), Some(vec![String::new()]))
        .expect_err("empty redirect_uri value is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_missing_request_redirect_uri_when_attestation_restricts_redirects() {
    let attestation = attestation(
        "verifier.example".to_owned(),
        Some(vec!["https://verifier.example/cb".to_owned()]),
    )
    .expect("test attestation is valid");
    let mut request = request();
    request.redirect_uri = None;

    let err = validate_verifier_attestation_binding(&request, &attestation, &[1_u8], 99)
        .expect_err("missing redirect_uri is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn accepts_missing_request_redirect_uri_without_attestation_redirect_restrictions() {
    let attestation =
        attestation("verifier.example".to_owned(), None).expect("test attestation is valid");
    let mut request = request();
    request.redirect_uri = None;

    validate_verifier_attestation_binding(&request, &attestation, &[1_u8], 99)
        .expect("unrestricted attestation does not require redirect_uri");
}

#[test]
fn rejects_expired_or_unbound_verifier_attestation() {
    let attestation =
        attestation("verifier.example".to_owned(), None).expect("test attestation is valid");

    for (public_key, now_unix) in [(&[2_u8][..], 99_u64), (&[1_u8][..], 100_u64)] {
        let error =
            validate_verifier_attestation_binding(&request(), &attestation, public_key, now_unix)
                .expect_err("attestation must bind the exact request key and remain unexpired");
        assert_eq!(
            error.reason(),
            WalletErrorReason::InvalidVerifierAttestation
        );
    }
}
