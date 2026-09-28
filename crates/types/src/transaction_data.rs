// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_codec::jcs::{canonicalize_json_text, canonicalize_trusted_json_value, JcsError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::zeroize_json::zeroize_json_value;
use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// Maximum JSON nesting canonicalized by this crate's transaction-data helper.
pub const MAX_TRANSACTION_DATA_JSON_DEPTH: usize = 128;

/// Maximum decoded JSON accepted for one transaction-data value.
pub const MAX_TRANSACTION_DATA_JSON_BYTES: usize = 256 * 1024;

/// Transaction data object from OpenID4VP 1.0 final.
#[derive(Clone, PartialEq)]
pub struct TransactionData {
    /// Application or profile-defined transaction type.
    transaction_type: String,
    /// Credential ids this transaction data applies to.
    credential_ids: Vec<String>,
    /// Profile-specific transaction data payload.
    payload: JsonValue,
    /// Exact base64url value received or deterministically built locally.
    encoded_value: String,
}

impl TransactionData {
    /// Construct transaction data and retain its deterministic wire encoding.
    pub fn new(
        transaction_type: String,
        credential_ids: Vec<String>,
        payload: JsonValue,
    ) -> Result<Self, OpenId4vpTypeError> {
        let mut value = Self {
            transaction_type,
            credential_ids,
            payload,
            encoded_value: String::new(),
        };
        validate_transaction_data(&value)?;
        let canonical = canonical_transaction_data_bytes(&value)?;
        value.encoded_value = bytes_to_base64url(&canonical);
        Ok(value)
    }

    /// Application or profile-defined transaction type.
    #[must_use]
    pub fn transaction_type(&self) -> &str {
        &self.transaction_type
    }

    /// Credential ids this transaction data applies to.
    #[must_use]
    pub fn credential_ids(&self) -> &[String] {
        &self.credential_ids
    }

    /// Profile-specific transaction data payload.
    #[must_use]
    pub const fn payload(&self) -> &JsonValue {
        &self.payload
    }

    /// Exact base64url string whose bytes are covered by transaction-data hashes.
    #[must_use]
    pub fn encoded_value(&self) -> &str {
        &self.encoded_value
    }
}

impl fmt::Debug for TransactionData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionData")
            .field("transaction_type", &self.transaction_type)
            .field("credential_id_count", &self.credential_ids.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl Zeroize for TransactionData {
    fn zeroize(&mut self) {
        self.transaction_type.zeroize();
        self.credential_ids.zeroize();
        zeroize_json_value(&mut self.payload);
        self.encoded_value.zeroize();
    }
}

impl Drop for TransactionData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TransactionData {}

impl Serialize for TransactionData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = encoded_transaction_data_string(self)
            .map_err(|_| serde::ser::Error::custom("invalid transaction data"))?;
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for TransactionData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        decode_transaction_data_string(&encoded)
            .map_err(|_| serde::de::Error::custom("invalid transaction data"))
    }
}

/// Transaction data hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionDataHashAlgorithm {
    /// SHA-256.
    #[serde(rename = "sha-256")]
    Sha256,
}

/// Fixed-size transaction data digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionDataHash {
    /// Hash algorithm.
    pub algorithm: TransactionDataHashAlgorithm,
    /// Digest bytes.
    pub digest: [u8; 32],
}

impl TransactionDataHash {
    /// Compute SHA-256 over caller-provided canonical transaction data bytes.
    pub fn sha256(canonical_transaction_data: &[u8]) -> Result<Self, OpenId4vpTypeError> {
        if canonical_transaction_data.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyValue,
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(canonical_transaction_data);
        let digest = hasher.finalize().into();
        Ok(Self {
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest,
        })
    }

    /// Compute SHA-256 over the exact received final-spec transaction data string.
    ///
    /// OpenID4VP hashes the base64url-encoded `transaction_data` member, not
    /// the decoded JSON object. This method validates the encoded value before
    /// hashing so callers can keep wire-level interop without accepting
    /// malformed transaction data.
    pub fn sha256_received_transaction_data_string(
        encoded: &str,
    ) -> Result<Self, OpenId4vpTypeError> {
        decode_transaction_data_string(encoded)?;
        Self::sha256(encoded.as_bytes())
    }

    /// Compute SHA-256 over the exact encoding retained by `TransactionData`.
    ///
    /// Decoded values retain their received base64url string; locally
    /// constructed values retain the deterministic encoding created by
    /// [`TransactionData::new`].
    pub fn sha256_transaction_data(
        transaction_data: &TransactionData,
    ) -> Result<Self, OpenId4vpTypeError> {
        let encoded = encoded_transaction_data_string(transaction_data)?;
        Self::sha256(encoded.as_bytes())
    }
}

/// Encode a transaction data object as the final-spec base64url string.
pub fn encoded_transaction_data_string(
    transaction_data: &TransactionData,
) -> Result<String, OpenId4vpTypeError> {
    validate_transaction_data(transaction_data)?;
    if transaction_data.encoded_value.is_empty() {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::InvalidEncoding,
        ));
    }
    Ok(transaction_data.encoded_value.clone())
}

/// Decode one final-spec base64url transaction data string.
pub fn decode_transaction_data_string(
    encoded: &str,
) -> Result<TransactionData, OpenId4vpTypeError> {
    if encoded.is_empty() {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::EmptyValue,
        ));
    }

    if encoded.len() > max_transaction_data_encoded_bytes()? {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }

    let bytes = Zeroizing::new(
        base64url_to_bytes(encoded)
            .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?,
    );
    if bytes.len() > MAX_TRANSACTION_DATA_JSON_BYTES {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }

    let json_text = core::str::from_utf8(&bytes)
        .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?;
    let canonical =
        Zeroizing::new(canonicalize_json_text(json_text).map_err(map_untrusted_jcs_error)?);
    if canonical.len() > MAX_TRANSACTION_DATA_JSON_BYTES {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }

    let object: JsonMap<String, JsonValue> = serde_json::from_str(&canonical)
        .map_err(|_| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidEncoding))?;
    transaction_data_from_object(
        SensitiveTransactionDataObject::new(object),
        Zeroizing::new(encoded.to_owned()),
    )
}

/// Build deterministic JSON bytes for OpenID4VP transaction data hashing.
pub fn canonical_transaction_data_bytes(
    transaction_data: &TransactionData,
) -> Result<Zeroizing<Vec<u8>>, OpenId4vpTypeError> {
    validate_transaction_data(transaction_data)?;
    let mut json = transaction_data_object_value(transaction_data)?;
    let canonical_result = canonicalize_trusted_json_value(&json);
    zeroize_json_value(&mut json);

    let canonical = Zeroizing::new(canonical_result.map_err(map_trusted_jcs_error)?);
    if canonical.len() > MAX_TRANSACTION_DATA_JSON_BYTES {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }

    Ok(Zeroizing::new(canonical.as_bytes().to_vec()))
}

fn max_transaction_data_encoded_bytes() -> Result<usize, OpenId4vpTypeError> {
    MAX_TRANSACTION_DATA_JSON_BYTES
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::JsonSizeExceeded))
}

fn map_untrusted_jcs_error(error: JcsError) -> OpenId4vpTypeError {
    let reason = match error {
        JcsError::DuplicateProperty => OpenId4vpTypeErrorReason::DuplicateJsonKey,
        JcsError::DepthExceeded => OpenId4vpTypeErrorReason::JsonDepthExceeded,
        _ => OpenId4vpTypeErrorReason::InvalidEncoding,
    };
    OpenId4vpTypeError::new(reason)
}

fn map_trusted_jcs_error(error: JcsError) -> OpenId4vpTypeError {
    let reason = match error {
        JcsError::DepthExceeded => OpenId4vpTypeErrorReason::JsonDepthExceeded,
        _ => OpenId4vpTypeErrorReason::SerializationFailed,
    };
    OpenId4vpTypeError::new(reason)
}

fn transaction_data_object_value(
    transaction_data: &TransactionData,
) -> Result<JsonValue, OpenId4vpTypeError> {
    let mut map = JsonMap::new();
    map.insert(
        "type".to_owned(),
        JsonValue::String(transaction_data.transaction_type.clone()),
    );
    map.insert(
        "credential_ids".to_owned(),
        JsonValue::Array(
            transaction_data
                .credential_ids
                .iter()
                .cloned()
                .map(JsonValue::String)
                .collect(),
        ),
    );
    let JsonValue::Object(payload) = &transaction_data.payload else {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::InvalidEncoding,
        ));
    };
    for (key, value) in payload {
        if key != "type" && key != "credential_ids" {
            map.insert(key.clone(), value.clone());
        }
    }
    Ok(JsonValue::Object(map))
}

fn transaction_data_from_object(
    mut object: SensitiveTransactionDataObject,
    mut encoded_value: Zeroizing<String>,
) -> Result<TransactionData, OpenId4vpTypeError> {
    let mut transaction_type = match object.0.remove("type") {
        Some(JsonValue::String(value)) => Zeroizing::new(value),
        Some(mut invalid) => {
            zeroize_json_value(&mut invalid);
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::InvalidEncoding,
            ));
        }
        None => {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::InvalidEncoding,
            ));
        }
    };
    let mut credential_values = match object.0.remove("credential_ids") {
        Some(JsonValue::Array(values)) => SensitiveJsonValues(values),
        Some(mut invalid) => {
            zeroize_json_value(&mut invalid);
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::InvalidEncoding,
            ));
        }
        None => {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::InvalidEncoding,
            ));
        }
    };
    let mut credential_ids = Zeroizing::new(Vec::with_capacity(credential_values.0.len()));
    while let Some(mut value) = credential_values.0.pop() {
        match value {
            JsonValue::String(mut value) => {
                credential_ids.push(core::mem::take(&mut value));
                value.zeroize();
            }
            _ => {
                zeroize_json_value(&mut value);
                return Err(OpenId4vpTypeError::new(
                    OpenId4vpTypeErrorReason::InvalidEncoding,
                ));
            }
        }
    }
    credential_ids.reverse();
    let payload = JsonValue::Object(core::mem::take(&mut object.0));
    let mut transaction_data = TransactionData {
        transaction_type: core::mem::take(&mut transaction_type),
        credential_ids: core::mem::take(&mut credential_ids),
        payload,
        encoded_value: core::mem::take(&mut encoded_value),
    };
    if let Err(error) = validate_transaction_data(&transaction_data) {
        transaction_data.zeroize();
        return Err(error);
    }
    Ok(transaction_data)
}

struct SensitiveTransactionDataObject(JsonMap<String, JsonValue>);

impl SensitiveTransactionDataObject {
    const fn new(value: JsonMap<String, JsonValue>) -> Self {
        Self(value)
    }
}

impl Drop for SensitiveTransactionDataObject {
    fn drop(&mut self) {
        let mut value = JsonValue::Object(core::mem::take(&mut self.0));
        zeroize_json_value(&mut value);
    }
}

struct SensitiveJsonValues(Vec<JsonValue>);

impl Drop for SensitiveJsonValues {
    fn drop(&mut self) {
        for value in &mut self.0 {
            zeroize_json_value(value);
        }
    }
}

fn validate_transaction_data(transaction_data: &TransactionData) -> Result<(), OpenId4vpTypeError> {
    if transaction_data.transaction_type.is_empty()
        || transaction_data.credential_ids.is_empty()
        || transaction_data.credential_ids.iter().any(String::is_empty)
    {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::EmptyValue,
        ));
    }
    if !transaction_data.payload.is_object() {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::InvalidEncoding,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "transaction_data_tests.rs"]
mod tests;
