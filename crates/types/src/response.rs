// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use reallyme_codec::jcs::{canonicalize_trusted_json_value, JcsError};
use reallyme_openid4vp_dcql::QueryId;
use serde::de::{
    value::MapAccessDeserializer, value::SeqAccessDeserializer, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::zeroize_json::zeroize_json_value;
use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// Maximum canonical JSON bytes accepted for an Authorization Response.
pub const MAX_AUTHORIZATION_RESPONSE_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Canonicalize one trusted JSON-native presentation value.
///
/// Format verifiers use this after cryptographic authentication to obtain a
/// deterministic digest and enforce their tighter retained-claim size limit.
/// The temporary tree and output owner are zeroized because disclosed claims
/// can contain personal data.
pub fn canonical_presentation_json_bytes(
    value: &JsonValue,
) -> Result<Zeroizing<Vec<u8>>, OpenId4vpTypeError> {
    let mut owned = value.clone();
    let canonical_result = canonicalize_trusted_json_value(&owned);
    zeroize_json_value(&mut owned);
    let canonical = Zeroizing::new(canonical_result.map_err(map_jcs_error)?);
    if canonical.len() > MAX_AUTHORIZATION_RESPONSE_JSON_BYTES {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }
    Ok(Zeroizing::new(canonical.as_bytes().to_vec()))
}

/// Presentation value carried in a `vp_token` entry.
#[derive(Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PresentationValue {
    /// Compact string presentation such as an SD-JWT VC presentation.
    Compact(String),
    /// JSON presentation value for formats with JSON-native responses.
    ///
    /// This is intentionally raw protocol JSON: OpenID4VP permits format-
    /// specific `vp_token` entries, and SDK/FFI layers must validate this value
    /// at their own external boundary before projecting it into platform types.
    Json(JsonValue),
}

impl<'de> Deserialize<'de> for PresentationValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PresentationValueVisitor)
    }
}

struct PresentationValueVisitor;

impl<'de> Visitor<'de> for PresentationValueVisitor {
    type Value = PresentationValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a compact presentation string or JSON presentation value")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(PresentationValue::Compact(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(PresentationValue::Compact(value))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(PresentationValue::Json(JsonValue::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(PresentationValue::Json(JsonValue::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(PresentationValue::Json(JsonValue::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(PresentationValue::Json(JsonValue::Number(number)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(PresentationValue::Json(JsonValue::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(PresentationValue::Json(JsonValue::Null))
    }

    fn visit_seq<A>(self, sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        JsonValue::deserialize(SeqAccessDeserializer::new(sequence)).map(PresentationValue::Json)
    }

    fn visit_map<A>(self, object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        JsonValue::deserialize(MapAccessDeserializer::new(object)).map(PresentationValue::Json)
    }
}

impl fmt::Debug for PresentationValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compact(value) => formatter
                .debug_struct("Compact")
                .field("byte_len", &value.len())
                .field("value", &"<redacted>")
                .finish(),
            Self::Json(_) => formatter
                .debug_struct("Json")
                .field("value", &"<redacted>")
                .finish(),
        }
    }
}

impl Zeroize for PresentationValue {
    fn zeroize(&mut self) {
        match self {
            Self::Compact(value) => value.zeroize(),
            Self::Json(value) => zeroize_json_value(value),
        }
    }
}

impl Drop for PresentationValue {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PresentationValue {}

/// Final OpenID4VP `vp_token` shape keyed by DCQL Credential Query id.
pub type VpToken = BTreeMap<QueryId, Vec<PresentationValue>>;

/// OpenID4VP Authorization Response.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// DCQL-keyed VP Token object.
    pub vp_token: VpToken,
    /// OIDC state echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl fmt::Debug for AuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationResponse")
            .field("query_count", &self.vp_token.len())
            .field("vp_token", &"<redacted>")
            .field("state", &self.state.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Zeroize for AuthorizationResponse {
    fn zeroize(&mut self) {
        for presentations in self.vp_token.values_mut() {
            presentations.zeroize();
        }
        self.state.zeroize();
    }
}

impl Drop for AuthorizationResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationResponse {}

impl AuthorizationResponse {
    /// Build a response for one DCQL Credential Query id.
    pub fn single(
        query_id: QueryId,
        presentations: Vec<PresentationValue>,
        state: Option<String>,
    ) -> Result<Self, OpenId4vpTypeError> {
        if presentations.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyPresentationList,
            ));
        }
        let mut vp_token = BTreeMap::new();
        vp_token.insert(query_id, presentations);
        Ok(Self { vp_token, state })
    }
}

/// Serialize a trusted, typed Authorization Response as bounded canonical JSON.
///
/// Compact JWE carries this JSON object as its plaintext. Keeping the operation
/// on the protocol type boundary ensures all wallet adapters apply the same
/// nesting, numeric, and output-size policy before encryption.
pub fn canonical_authorization_response_bytes(
    response: &AuthorizationResponse,
) -> Result<Zeroizing<Vec<u8>>, OpenId4vpTypeError> {
    let mut vp_token = JsonMap::new();
    for (query_id, presentations) in &response.vp_token {
        let values = presentations
            .iter()
            .map(|presentation| match presentation {
                PresentationValue::Compact(value) => JsonValue::String(value.clone()),
                PresentationValue::Json(value) => value.clone(),
            })
            .collect();
        vp_token.insert(query_id.as_str().to_owned(), JsonValue::Array(values));
    }
    let mut object = JsonMap::new();
    object.insert("vp_token".to_owned(), JsonValue::Object(vp_token));
    if let Some(state) = response.state.as_ref() {
        object.insert("state".to_owned(), JsonValue::String(state.clone()));
    }
    let mut value = JsonValue::Object(object);
    let canonical_result = canonicalize_trusted_json_value(&value);
    zeroize_json_value(&mut value);
    let canonical = Zeroizing::new(canonical_result.map_err(map_jcs_error)?);
    if canonical.len() > MAX_AUTHORIZATION_RESPONSE_JSON_BYTES {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
        ));
    }
    Ok(Zeroizing::new(canonical.as_bytes().to_vec()))
}

fn map_jcs_error(error: JcsError) -> OpenId4vpTypeError {
    let reason = match error {
        JcsError::DepthExceeded => OpenId4vpTypeErrorReason::JsonDepthExceeded,
        JcsError::DuplicateProperty => OpenId4vpTypeErrorReason::DuplicateJsonKey,
        _ => OpenId4vpTypeErrorReason::SerializationFailed,
    };
    OpenId4vpTypeError::new(reason)
}

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;
