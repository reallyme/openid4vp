// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::{AuthorizationRequestObject, TransactionData};
use serde_json::json;

use super::WalletTransactionDataPolicy;
use crate::{
    validate_unsigned_dc_api_request_with_transaction_data_policy,
    validate_wallet_request_object_with_transaction_data_policy, WalletError, WalletErrorReason,
};

fn validate_signed_request(
    request: &AuthorizationRequestObject,
    policy: WalletTransactionDataPolicy<'_>,
) -> Result<(), WalletError> {
    let mut signed = request.clone();
    signed.client_id = Some(
        reallyme_openid4vp_types::ClientIdentifier::parse(
            "decentralized_identifier:did:example:verifier",
        )
        .expect("valid test client identifier"),
    );
    signed.expected_origins = Some(vec!["https://rp.example".to_owned()]);
    validate_wallet_request_object_with_transaction_data_policy(
        &signed,
        Some("https://rp.example"),
        10,
        policy,
    )
}

fn request(holder_binding: bool, ids: &[&str]) -> AuthorizationRequestObject {
    let mut request: AuthorizationRequestObject = serde_json::from_value(json!({
        "response_type":"vp_token", "response_mode":"dc_api", "nonce":"0123456789abcdef",
        "dcql_query":{"credentials":[{
            "id":"pid", "format":"dc+sd-jwt", "meta":{"vct_values":["urn:example:pid"]},
            "require_cryptographic_holder_binding":holder_binding
        }]}
    }))
    .expect("valid test request");
    request.transaction_data = Some(vec![TransactionData::new(
        "payment".to_owned(),
        ids.iter().map(|id| (*id).to_owned()).collect(),
        json!({"amount":"10.00"}),
    )
    .expect("valid transaction object")]);
    request
}

#[test]
fn accepts_transaction_data_for_a_holder_bound_sd_jwt_query() {
    let policy = WalletTransactionDataPolicy::new(&["payment"]).expect("valid policy");
    let request = request(true, &["pid"]);
    assert!(policy.validate(&request).is_ok());
    assert!(validate_signed_request(&request, policy).is_ok());
    assert!(
        validate_unsigned_dc_api_request_with_transaction_data_policy(&request, policy).is_ok()
    );
}

#[test]
fn rejects_unknown_transaction_credential_ids_even_after_a_valid_reference() {
    let policy = WalletTransactionDataPolicy::new(&["payment"]).expect("valid policy");
    for ids in [
        &["missing"][..],
        &["pid", "missing"][..],
        &["missing", "pid"][..],
    ] {
        let request = request(true, ids);
        assert_eq!(
            validate_signed_request(&request, policy).map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidTransactionData)
        );
        assert_eq!(
            policy.validate(&request).map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidTransactionData)
        );
        assert_eq!(
            validate_unsigned_dc_api_request_with_transaction_data_policy(&request, policy)
                .map_err(|error| error.reason()),
            Err(WalletErrorReason::InvalidTransactionData)
        );
    }
}

#[test]
fn rejects_sd_jwt_transaction_data_without_cryptographic_holder_binding() {
    let policy = WalletTransactionDataPolicy::new(&["payment"]).expect("valid policy");
    let request = request(false, &["pid"]);
    assert_eq!(
        validate_signed_request(&request, policy).map_err(|error| error.reason()),
        Err(WalletErrorReason::InvalidTransactionData)
    );
    assert_eq!(
        policy.validate(&request).map_err(|error| error.reason()),
        Err(WalletErrorReason::InvalidTransactionData)
    );
    assert_eq!(
        validate_unsigned_dc_api_request_with_transaction_data_policy(&request, policy)
            .map_err(|error| error.reason()),
        Err(WalletErrorReason::InvalidTransactionData)
    );
}
