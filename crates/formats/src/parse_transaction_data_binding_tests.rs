// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_codec::base64url::bytes_to_base64url;
use serde_json::{json, Value as JsonValue};

use super::{
    parse_transaction_data_binding, TransactionDataHashAlgorithm, MAX_TRANSACTION_DATA_HASHES,
    SHA256_DIGEST_BYTES,
};
use crate::sd_jwt::SdJwtFormatErrorReason;

#[test]
fn parses_exact_sha256_transaction_data_binding() {
    let payload = json!({
        "transaction_data_hashes": [bytes_to_base64url(&[11; SHA256_DIGEST_BYTES])],
        "transaction_data_hashes_alg": "sha-256"
    });

    let (hashes, algorithm) =
        parse_transaction_data_binding(&payload).expect("valid binding parses");

    assert_eq!(hashes, vec![[11; SHA256_DIGEST_BYTES]]);
    assert_eq!(algorithm, Some(TransactionDataHashAlgorithm::Sha256));
}

#[test]
fn rejects_malformed_or_incomplete_transaction_data_binding() {
    let oversized = vec![
        JsonValue::String(bytes_to_base64url(&[7; SHA256_DIGEST_BYTES]));
        MAX_TRANSACTION_DATA_HASHES + 1
    ];
    for payload in [
        json!({"transaction_data_hashes": ["AA"]}),
        json!({"transaction_data_hashes": []}),
        json!({"transaction_data_hashes_alg": "sha-256"}),
        json!({
            "transaction_data_hashes": [bytes_to_base64url(&[7; SHA256_DIGEST_BYTES])],
            "transaction_data_hashes_alg": "sha-512"
        }),
        json!({
            "transaction_data_hashes": oversized,
            "transaction_data_hashes_alg": "sha-256"
        }),
    ] {
        let error = parse_transaction_data_binding(&payload)
            .expect_err("malformed transaction data binding must fail closed");
        assert_eq!(error.reason(), SdJwtFormatErrorReason::InvalidHolderBinding);
    }
}
