// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_types::{
    canonical_transaction_data_bytes, decode_transaction_data_string, TransactionData,
    TransactionDataHash,
};

fuzz_target!(|data: &[u8]| {
    let encoded = reallyme_codec::base64url::bytes_to_base64url(data);
    let _ = decode_transaction_data_string(&encoded);
    if let Ok(transaction_data) = serde_json::from_slice::<TransactionData>(data) {
        if let Ok(canonical) = canonical_transaction_data_bytes(&transaction_data) {
            let _ = TransactionDataHash::sha256(&canonical);
        }
        let _ = TransactionDataHash::sha256_transaction_data(&transaction_data);
    }
});
