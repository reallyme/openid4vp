// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use serde_json::json;

use crate::transaction_data::{
    canonical_transaction_data_bytes, decode_transaction_data_string,
    encoded_transaction_data_string, TransactionData, TransactionDataHash,
    TransactionDataHashAlgorithm, MAX_TRANSACTION_DATA_JSON_BYTES, MAX_TRANSACTION_DATA_JSON_DEPTH,
};
use crate::zeroize_json::{TEST_ZEROIZE_SENTINEL, ZEROIZE_OBSERVATION};
use crate::OpenId4vpTypeErrorReason;

fn reset_zeroize_observation() {
    ZEROIZE_OBSERVATION.with(|observation| observation.set((0, 0)));
}

fn assert_sentinel_was_cleared() {
    ZEROIZE_OBSERVATION.with(|observation| {
        let (observed, cleared) = observation.get();
        assert!(
            observed > 0,
            "the transaction sentinel reached a zeroizing owner"
        );
        assert_eq!(cleared, observed, "every observed sentinel was cleared");
    });
}

#[test]
fn canonicalizes_transaction_data_with_jcs() {
    let transaction_data = TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"z": 1.0, "a": {"d": 4, "c": 3}}),
    )
    .expect("test transaction data is valid");

    let canonical = canonical_transaction_data_bytes(&transaction_data)
        .expect("transaction data canonicalizes");

    assert_eq!(
        canonical.as_slice(),
        br#"{"a":{"c":3,"d":4},"credential_ids":["pid"],"type":"payment","z":1}"#
    );
}

#[test]
fn hashes_transaction_data_from_canonical_json() {
    let transaction_data = TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"amount": "10.00", "currency": "EUR"}),
    )
    .expect("test transaction data is valid");

    let hash = TransactionDataHash::sha256_transaction_data(&transaction_data)
        .expect("transaction data hashes");

    assert_eq!(hash.algorithm, TransactionDataHashAlgorithm::Sha256);
    assert_eq!(hash.digest.len(), 32);
}

#[test]
fn hashes_received_transaction_data_string_without_recanonicalizing() {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(
        br#"{
          "payload": {"currency": "EUR", "amount": "10.00"},
          "credential_ids": ["pid"],
          "type": "payment"
        }"#,
    );

    let received_hash = TransactionDataHash::sha256_received_transaction_data_string(&encoded)
        .expect("received transaction data hashes");
    let direct_hash =
        TransactionDataHash::sha256(encoded.as_bytes()).expect("encoded string hashes");
    let decoded = decode_transaction_data_string(&encoded).expect("transaction data decodes");
    let local_hash = TransactionDataHash::sha256_transaction_data(&decoded)
        .expect("locally constructed transaction data hashes");

    assert_eq!(received_hash, direct_hash);
    assert_eq!(received_hash, local_hash);
    assert_eq!(decoded.encoded_value(), encoded);
}

#[test]
fn serializes_transaction_data_as_base64url_string() {
    let transaction_data = TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"amount": "10.00"}),
    )
    .expect("test transaction data is valid");

    let encoded =
        encoded_transaction_data_string(&transaction_data).expect("transaction data encodes");
    let json = serde_json::to_value(&transaction_data).expect("transaction data serializes");
    let decoded = decode_transaction_data_string(&encoded).expect("transaction data decodes");

    assert_eq!(json, json!(encoded));
    assert_eq!(decoded, transaction_data);
}

#[test]
fn decodes_spec_shaped_transaction_data_object() {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(
        br#"{"type":"payment","credential_ids":["pid"],"amount":"10.00","currency":"EUR"}"#,
    );

    let decoded =
        decode_transaction_data_string(&encoded).expect("spec-shaped transaction data decodes");

    assert_eq!(decoded.transaction_type(), "payment");
    assert_eq!(decoded.credential_ids(), &["pid"]);
    assert_eq!(
        decoded.payload(),
        &json!({"amount": "10.00", "currency": "EUR"})
    );
}

#[test]
fn rejects_non_object_transaction_data_payload() {
    let err = TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!("non-object"),
    )
    .expect_err("transaction data payload must use final object shape");

    assert_eq!(err.reason(), OpenId4vpTypeErrorReason::InvalidEncoding);
}

#[test]
fn rejects_empty_transaction_data_credential_ids() {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(
        br#"{"type":"payment","credential_ids":[],"amount":"10.00"}"#,
    );

    let err = decode_transaction_data_string(&encoded)
        .expect_err("credential_ids is required and non-empty");

    assert_eq!(err.reason(), OpenId4vpTypeErrorReason::EmptyValue);
}

#[test]
fn rejects_duplicate_transaction_data_json_keys() {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(
        br#"{"type":"payment","type":"transfer","credential_ids":["pid"]}"#,
    );

    let err = decode_transaction_data_string(&encoded)
        .expect_err("duplicate transaction data properties are rejected");

    assert_eq!(err.reason(), OpenId4vpTypeErrorReason::DuplicateJsonKey);
}

#[test]
fn rejects_oversized_transaction_data_json() {
    let oversized = vec![b'a'; MAX_TRANSACTION_DATA_JSON_BYTES + 1];
    let encoded = reallyme_codec::base64url::bytes_to_base64url(&oversized);

    let err = decode_transaction_data_string(&encoded)
        .expect_err("oversized transaction data is rejected before parsing");

    assert_eq!(err.reason(), OpenId4vpTypeErrorReason::JsonSizeExceeded);
}

#[test]
fn rejects_over_deep_transaction_data_json() {
    let mut payload = json!(null);
    for _ in 0..=MAX_TRANSACTION_DATA_JSON_DEPTH {
        payload = json!([payload]);
    }
    let err = TransactionData::new(
        "payment".to_owned(),
        vec!["pid".to_owned()],
        json!({"nested": payload}),
    )
    .expect_err("transaction data canonicalization has its own depth guard");

    assert_eq!(err.reason(), OpenId4vpTypeErrorReason::JsonDepthExceeded);
}

#[test]
fn clears_transaction_payload_after_success() {
    reset_zeroize_observation();
    let encoded = transaction_fixture(&format!(
        r#"{{"type":"payment","credential_ids":["pid"],"secret":"{TEST_ZEROIZE_SENTINEL}"}}"#
    ));
    let decoded = decode_transaction_data_string(&encoded).expect("test transaction data decodes");
    drop(decoded);
    assert_sentinel_was_cleared();
}

#[test]
fn clears_transaction_tree_when_type_is_missing_or_wrong() {
    for fixture in [
        format!(r#"{{"credential_ids":["pid"],"secret":"{TEST_ZEROIZE_SENTINEL}"}}"#),
        format!(r#"{{"type":7,"credential_ids":["pid"],"secret":"{TEST_ZEROIZE_SENTINEL}"}}"#),
    ] {
        reset_zeroize_observation();
        let error = decode_transaction_data_string(&transaction_fixture(&fixture))
            .expect_err("missing or non-string type fails closed");
        assert_eq!(error.reason(), OpenId4vpTypeErrorReason::InvalidEncoding);
        assert_sentinel_was_cleared();
    }
}

#[test]
fn clears_transaction_tree_on_wrong_or_late_invalid_credential_id() {
    for fixture in [
        format!(r#"{{"type":"payment","credential_ids":7,"secret":"{TEST_ZEROIZE_SENTINEL}"}}"#),
        format!(r#"{{"type":"payment","credential_ids":["{TEST_ZEROIZE_SENTINEL}",7]}}"#),
    ] {
        reset_zeroize_observation();
        let error = decode_transaction_data_string(&transaction_fixture(&fixture))
            .expect_err("invalid credential identifier member fails closed");
        assert_eq!(error.reason(), OpenId4vpTypeErrorReason::InvalidEncoding);
        assert_sentinel_was_cleared();
    }
}

#[test]
fn clears_transaction_tree_on_late_domain_validation_failure() {
    reset_zeroize_observation();
    let encoded = transaction_fixture(&format!(
        r#"{{"type":"","credential_ids":["pid"],"secret":"{TEST_ZEROIZE_SENTINEL}"}}"#
    ));
    let error = decode_transaction_data_string(&encoded)
        .expect_err("empty transaction type fails domain validation");
    assert_eq!(error.reason(), OpenId4vpTypeErrorReason::EmptyValue);
    assert_sentinel_was_cleared();
}

fn transaction_fixture(json: &str) -> String {
    reallyme_codec::base64url::bytes_to_base64url(json.as_bytes())
}
