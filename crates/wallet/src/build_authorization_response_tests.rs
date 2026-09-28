// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{
    CredentialFormat, CredentialQuery, CredentialSetQuery, DcqlQuery, QueryId,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, PresentationValue, ResponseMode, ResponseType, TransactionData,
    TransactionDataHashAlgorithm,
};
use serde_json::Map as JsonMap;

use super::{
    build_authorization_response, TransactionDataPresentationVerificationContext,
    TransactionDataPresentationVerifier, WalletSelectedPresentation, WalletSelectedPresentationSet,
};
use crate::{VerifiedWalletRequest, WalletError, WalletErrorReason};

struct FixtureTransactionDataVerifier;

impl TransactionDataPresentationVerifier for FixtureTransactionDataVerifier {
    fn verify_transaction_data_presentation(
        &self,
        context: TransactionDataPresentationVerificationContext<'_>,
    ) -> Result<(), WalletError> {
        let PresentationValue::Compact(presentation) = context.presentation() else {
            return Err(WalletError::new(
                WalletErrorReason::InvalidTransactionDataResponse,
            ));
        };
        if presentation != "presentation"
            || context.query_id().as_str() != "pid"
            || context.format().as_str() != CredentialFormat::DC_SD_JWT
            || context.ordered_transaction_data().len() != 1
            || context.algorithm() != TransactionDataHashAlgorithm::Sha256
        {
            return Err(WalletError::new(
                WalletErrorReason::InvalidTransactionDataResponse,
            ));
        }
        Ok(())
    }
}

fn build_response(
    request: &VerifiedWalletRequest,
    selected: WalletSelectedPresentationSet,
) -> Result<reallyme_openid4vp_types::AuthorizationResponse, WalletError> {
    build_authorization_response(request, selected, &FixtureTransactionDataVerifier)
}

#[test]
fn builds_dcql_keyed_response_and_echoes_state() {
    let request = request(false, false);
    let response = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("pid", "presentation")]),
    )
    .expect("valid selection builds a response");

    assert_eq!(response.state.as_deref(), Some("fedcba9876543210"));
    assert_eq!(response.vp_token.len(), 1);
    assert_eq!(response.vp_token.values().next().map(Vec::len), Some(1));
}

#[test]
fn rejects_empty_unknown_and_excess_single_query_selections() {
    let request = request(false, false);
    let empty = build_response(&request, WalletSelectedPresentationSet::new(Vec::new()))
        .expect_err("an empty response must fail closed");
    assert_eq!(
        empty.reason(),
        WalletErrorReason::MissingSelectedPresentation
    );

    let unknown = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("other", "presentation")]),
    )
    .expect_err("an unknown query id must fail closed");
    assert_eq!(
        unknown.reason(),
        WalletErrorReason::UnknownSelectedCredentialQuery
    );

    let excessive = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![
            selected("pid", "first"),
            selected("pid", "second"),
        ]),
    )
    .expect_err("a single-valued query cannot receive two presentations");
    assert_eq!(
        excessive.reason(),
        WalletErrorReason::SelectedPresentationCardinalityMismatch
    );
}

#[test]
fn requires_every_query_when_no_credential_sets_are_present() {
    let mut request = request(false, false);
    request
        .request_mut_for_test()
        .dcql_query
        .credentials
        .push(credential_query("address"));

    let error = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("pid", "presentation")]),
    )
    .expect_err("all credential queries are required without credential_sets");

    assert_eq!(
        error.reason(),
        WalletErrorReason::UnsatisfiedRequiredCredentialQuery
    );
}

#[test]
fn requires_one_complete_option_from_each_required_credential_set() {
    let mut request = request(false, false);
    request
        .request_mut_for_test()
        .dcql_query
        .credentials
        .push(credential_query("address"));
    request
        .request_mut_for_test()
        .dcql_query
        .credentials
        .push(credential_query("passport"));
    request.request_mut_for_test().dcql_query.credential_sets = Some(vec![CredentialSetQuery {
        options: vec![
            vec![query_id("pid"), query_id("address")],
            vec![query_id("passport")],
        ],
        required: true,
    }]);

    let partial = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("pid", "presentation")]),
    )
    .expect_err("a partial credential-set option must fail closed");
    assert_eq!(
        partial.reason(),
        WalletErrorReason::UnsatisfiedRequiredCredentialQuery
    );

    let response = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("passport", "presentation")]),
    )
    .expect("one complete required-set option is sufficient");
    assert!(response.vp_token.contains_key(&query_id("passport")));
}

#[test]
fn enforces_transaction_data_response_binding() {
    let request = request(false, true);
    let response = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("pid", "presentation")]),
    )
    .expect("the format verifier authenticates the exact transaction-bound proof");
    let json = serde_json::to_value(response).expect("response serializes");
    assert!(json.get("transaction_data_hashes").is_none());
    assert!(json.get("transaction_data_hashes_alg").is_none());
}

#[test]
fn rejects_unrelated_presentation_even_when_detached_hashes_would_be_correct() {
    let request = request(false, true);
    let error = build_response(
        &request,
        WalletSelectedPresentationSet::new(vec![selected("pid", "unrelated-presentation")]),
    )
    .expect_err("an unrelated presentation must fail before response serialization");

    assert_eq!(
        error.reason(),
        WalletErrorReason::InvalidTransactionDataResponse
    );
}

fn selected(query_id: &str, value: &str) -> WalletSelectedPresentation {
    WalletSelectedPresentation::new(
        self::query_id(query_id),
        PresentationValue::Compact(value.to_owned()),
    )
}

fn query_id(value: &str) -> QueryId {
    QueryId::parse(value).expect("test query id is valid")
}

fn credential_query(id: &str) -> CredentialQuery {
    CredentialQuery {
        id: query_id(id),
        format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
            .expect("test format is valid"),
        multiple: false,
        meta: JsonMap::new(),
        trusted_authorities: None,
        require_cryptographic_holder_binding: true,
        claims: None,
        claim_sets: None,
    }
}

fn request(multiple: bool, transaction_data: bool) -> VerifiedWalletRequest {
    VerifiedWalletRequest::for_test(AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPostJwt),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                multiple,
                ..credential_query("pid")
            }],
            credential_sets: None,
        },
        transaction_data: transaction_data.then(|| {
            vec![TransactionData::new(
                "urn:example:transaction".to_owned(),
                vec!["pid".to_owned()],
                serde_json::json!({"amount": 1}),
            )
            .expect("test transaction data is valid")]
        }),
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    })
}
