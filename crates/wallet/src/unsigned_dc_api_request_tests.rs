// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType, TransactionData,
};
use serde_json::{json, Map as JsonMap};

use super::{
    validate_unsigned_dc_api_request, validate_unsigned_dc_api_request_with_transaction_data_policy,
};
use crate::{WalletErrorReason, WalletTransactionDataPolicy};

fn unsigned_request() -> AuthorizationRequestObject {
    let mut credential_meta = JsonMap::new();
    credential_meta.insert("doctype_value".to_owned(), json!("org.iso.18013.5.1.mDL"));
    AuthorizationRequestObject {
        client_id: None,
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
                    .expect("test format is valid"),
                multiple: false,
                meta: credential_meta,
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
fn accepts_unsigned_dc_api_request_and_ignores_identity_members() {
    let mut request = unsigned_request();
    request.client_id = Some(
        ClientIdentifier::parse("x509_hash:ignored")
            .expect("test client id is syntactically valid"),
    );
    request.expected_origins = Some(vec!["https://wrong.example".to_owned()]);
    request.iss = Some("ignored issuer".to_owned());

    validate_unsigned_dc_api_request(&request)
        .expect("unsigned browser-origin requests ignore identity request members");
}

#[test]
fn rejects_unsigned_dc_api_request_without_nonce() {
    let mut request = unsigned_request();
    request.nonce.clear();

    let error = validate_unsigned_dc_api_request(&request)
        .expect_err("nonce remains mandatory for unsigned DC API requests");

    assert_eq!(
        error.reason(),
        WalletErrorReason::InvalidAuthorizationRequestTransport
    );
}

#[test]
fn rejects_unsigned_dc_api_request_with_response_endpoint() {
    let mut request = unsigned_request();
    request.response_uri = Some("https://verifier.example/response".to_owned());

    let error = validate_unsigned_dc_api_request(&request)
        .expect_err("DC API requests must return through the browser API");

    assert_eq!(
        error.reason(),
        WalletErrorReason::InvalidAuthorizationRequestTransport
    );
}

#[test]
fn unsigned_dc_api_transaction_data_requires_explicit_type_policy() {
    let mut request = unsigned_request();
    request.transaction_data = Some(vec![TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"payment_data": {"currency": "CHF"}}),
    )
    .expect("test transaction data is valid")]);

    let default_error = validate_unsigned_dc_api_request(&request)
        .expect_err("unsigned requests also reject unknown transaction semantics");
    assert_eq!(
        default_error.reason(),
        WalletErrorReason::InvalidTransactionData
    );

    let supported_types = ["payment"];
    let policy = WalletTransactionDataPolicy::new(&supported_types)
        .expect("test policy contains one supported type");
    validate_unsigned_dc_api_request_with_transaction_data_policy(&request, policy)
        .expect("explicitly supported transaction semantics are accepted");
}
