// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use serde_json::Value as JsonValue;

use crate::sd_jwt::{SdJwtFormatError, SdJwtFormatErrorReason};

const SHA256_DIGEST_BYTES: usize = 32;
const MAX_TRANSACTION_DATA_HASHES: usize = 64;

pub(crate) fn parse_transaction_data_binding(
    payload: &JsonValue,
) -> Result<
    (
        Vec<[u8; SHA256_DIGEST_BYTES]>,
        Option<TransactionDataHashAlgorithm>,
    ),
    SdJwtFormatError,
> {
    let algorithm = match payload.get("transaction_data_hashes_alg") {
        None => None,
        Some(JsonValue::String(value)) if value == "sha-256" => {
            Some(TransactionDataHashAlgorithm::Sha256)
        }
        Some(_) => return Err(invalid_holder_binding()),
    };
    let Some(values) = payload.get("transaction_data_hashes") else {
        if algorithm.is_some() {
            return Err(invalid_holder_binding());
        }
        return Ok((Vec::new(), None));
    };
    let values = values.as_array().ok_or_else(invalid_holder_binding)?;
    if values.is_empty() || values.len() > MAX_TRANSACTION_DATA_HASHES {
        return Err(invalid_holder_binding());
    }
    let mut hashes = Vec::with_capacity(values.len());
    for value in values {
        let encoded = value.as_str().ok_or_else(invalid_holder_binding)?;
        let decoded = reallyme_codec::base64url::base64url_to_bytes(encoded)
            .map_err(|_| invalid_holder_binding())?;
        let digest =
            <[u8; SHA256_DIGEST_BYTES]>::try_from(decoded).map_err(|_| invalid_holder_binding())?;
        hashes.push(digest);
    }
    Ok((hashes, algorithm))
}

fn invalid_holder_binding() -> SdJwtFormatError {
    SdJwtFormatError::new(SdJwtFormatErrorReason::InvalidHolderBinding)
}

#[cfg(test)]
#[path = "parse_transaction_data_binding_tests.rs"]
mod tests;
