// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::cell::Cell;
use core::fmt;

use serde::de::{
    DeserializeOwned, DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor,
};
use serde::{Deserializer, Serialize};
use serde_json::{Map as JsonMap, Number as JsonNumber, Value as JsonValue};
use zeroize::Zeroizing;

use crate::OpenId4VpProtoError;

/// Maximum canonical JSON bytes accepted for DCQL at protobuf boundaries.
pub const MAX_DCQL_JSON_BYTES: usize = 256 * 1024;
/// Maximum canonical JSON bytes accepted for client metadata.
pub const MAX_CLIENT_METADATA_JSON_BYTES: usize = 256 * 1024;
/// Maximum canonical JSON bytes accepted for one transaction-data payload.
pub const MAX_TRANSACTION_DATA_JSON_BYTES: usize = 256 * 1024;
/// Maximum canonical JSON bytes accepted for one presentation value.
pub const MAX_PRESENTATION_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Maximum nesting depth accepted for JSON embedded in protobuf fields.
pub const MAX_SENSITIVE_JSON_NESTING_DEPTH: usize = 64;

#[derive(Clone, Copy)]
enum JsonBoundaryFailure {
    DuplicateKey,
    NestingTooDeep,
}

#[derive(Clone, Copy)]
struct StrictJsonSeed<'a> {
    depth: usize,
    failure: &'a Cell<Option<JsonBoundaryFailure>>,
}

impl StrictJsonSeed<'_> {
    fn child<E: DeError>(self) -> Result<Self, E> {
        let depth = self.depth.checked_add(1).ok_or_else(|| {
            self.failure.set(Some(JsonBoundaryFailure::NestingTooDeep));
            E::custom("JSON nesting exceeds policy")
        })?;
        Ok(Self {
            depth,
            failure: self.failure,
        })
    }
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed<'_> {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_SENSITIVE_JSON_NESTING_DEPTH {
            self.failure.set(Some(JsonBoundaryFailure::NestingTooDeep));
            return Err(D::Error::custom("JSON nesting exceeds policy"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { seed: self })
    }
}

struct StrictJsonVisitor<'a> {
    seed: StrictJsonSeed<'a>,
}

struct SensitiveJsonValue(JsonValue);

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
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

struct SensitiveJsonMap(JsonMap<String, JsonValue>);

impl Drop for SensitiveJsonMap {
    fn drop(&mut self) {
        let old = core::mem::take(&mut self.0);
        for (mut key, mut value) in old {
            zeroize_sensitive_string(&mut key);
            zeroize_json_value(&mut value);
        }
    }
}

fn zeroize_sensitive_string(value: &mut String) {
    // `cfg!(test)` is a compile-time constant. Production builds therefore
    // remove the observation branch while tests can prove that each RAII
    // owner actually cleared its sensitive string before releasing storage.
    let observe_test_zeroization = cfg!(test) && value == TEST_ZEROIZE_SENTINEL;
    zeroize::Zeroize::zeroize(value);
    if observe_test_zeroization {
        ZEROIZE_OBSERVATION.with(|observation| {
            let (observed, cleared) = observation.get();
            observation.set((
                observed.saturating_add(1),
                cleared + usize::from(value.is_empty()),
            ));
        });
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(value) => zeroize_sensitive_string(value),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(values) => {
            let old = core::mem::take(values);
            for (mut key, mut value) in old {
                zeroize_sensitive_string(&mut key);
                zeroize_json_value(&mut value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
    *value = JsonValue::Null;
}

const TEST_ZEROIZE_SENTINEL: &str = "sensitive-json-zeroize-sentinel";

std::thread_local! {
    static ZEROIZE_OBSERVATION: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
}

impl<'de> Visitor<'de> for StrictJsonVisitor<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value within OpenID4VP boundary policy")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(JsonNumber::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(JsonValue::Number(JsonNumber::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        JsonNumber::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(JsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(JsonValue::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.seed.child()?.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = SensitiveJsonValues(Vec::new());
        let child = self.seed.child()?;
        while let Some(value) = sequence.next_element_seed(child)? {
            values.0.push(value);
        }
        Ok(JsonValue::Array(core::mem::take(&mut values.0)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = SensitiveJsonMap(JsonMap::new());
        let child = self.seed.child()?;
        while let Some(key) = object.next_key::<String>()? {
            if values.0.contains_key(&key) {
                self.seed
                    .failure
                    .set(Some(JsonBoundaryFailure::DuplicateKey));
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = object.next_value_seed(child)?;
            values.0.insert(key, value);
        }
        Ok(JsonValue::Object(core::mem::take(&mut values.0)))
    }
}

pub(crate) fn serialize_sensitive_json<T>(
    value: &T,
    max_bytes: usize,
) -> Result<Vec<u8>, OpenId4VpProtoError>
where
    T: Serialize,
{
    let mut encoded = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *encoded, value).map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    if encoded.len() > max_bytes {
        return Err(OpenId4VpProtoError::JsonTooLarge);
    }
    validate_sensitive_json(&encoded, max_bytes)?;
    Ok(core::mem::take(&mut *encoded))
}

pub(crate) fn deserialize_sensitive_json<T>(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<T, OpenId4VpProtoError>
where
    T: DeserializeOwned,
{
    decode_bounded_json(bytes, max_bytes)
}

/// Decode JSON with byte, nesting, duplicate-key, and trailing-data checks.
///
/// This helper exists for spec-native JSON embedded inside otherwise typed
/// protocol boundaries. It must not be used to introduce a parallel SDK DTO.
pub fn decode_bounded_json<T>(bytes: &[u8], max_bytes: usize) -> Result<T, OpenId4VpProtoError>
where
    T: DeserializeOwned,
{
    let value = parse_strict_json_value(bytes, max_bytes)?;
    T::deserialize(&value.0).map_err(|_| OpenId4VpProtoError::JsonDeserialize)
}

/// Encode JSON with byte and nesting checks under a zeroizing owner.
pub fn encode_bounded_json<T>(
    value: &T,
    max_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError>
where
    T: Serialize,
{
    serialize_sensitive_json(value, max_bytes).map(Zeroizing::new)
}

pub(crate) fn serialize_sensitive_json_value<T>(
    value: &T,
    max_bytes: usize,
) -> Result<JsonValue, OpenId4VpProtoError>
where
    T: Serialize,
{
    let bytes = Zeroizing::new(serialize_sensitive_json(value, max_bytes)?);
    let mut value = parse_strict_json_value(&bytes, max_bytes)?;
    Ok(core::mem::replace(&mut value.0, JsonValue::Null))
}

fn validate_sensitive_json(bytes: &[u8], max_bytes: usize) -> Result<(), OpenId4VpProtoError> {
    parse_strict_json_value(bytes, max_bytes).map(|_| ())
}

fn parse_strict_json_value(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<SensitiveJsonValue, OpenId4VpProtoError> {
    if bytes.len() > max_bytes {
        return Err(OpenId4VpProtoError::JsonTooLarge);
    }

    let failure = Cell::new(None);
    let seed = StrictJsonSeed {
        depth: 0,
        failure: &failure,
    };
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = seed
        .deserialize(&mut deserializer)
        .map_err(|_| match failure.get() {
            Some(JsonBoundaryFailure::DuplicateKey) => OpenId4VpProtoError::JsonDuplicateKey,
            Some(JsonBoundaryFailure::NestingTooDeep) => OpenId4VpProtoError::JsonNestingTooDeep,
            None => OpenId4VpProtoError::JsonDeserialize,
        })?;
    deserializer
        .end()
        .map_err(|_| OpenId4VpProtoError::JsonDeserialize)?;
    Ok(SensitiveJsonValue(value))
}

#[cfg(test)]
#[path = "sensitive_json_tests.rs"]
mod tests;
