// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict JSON guard used by the conformance corpus.
//!
//! `serde_json` accepts duplicate object names by taking the last value. That
//! behavior is not suitable for malicious protocol corpora because duplicate
//! names can hide conflicting security-relevant fields. The harness keeps this
//! policy explicit so boundary parsers can be measured against it.

use std::collections::BTreeSet;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};

use crate::error::{ConformanceError, ConformanceResult};

const MAX_JSON_NESTING_DEPTH: usize = 64;

/// Validate JSON syntax, reject duplicate object names, and enforce a nesting limit.
pub fn validate_strict_json(input: &str) -> ConformanceResult<()> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    StrictJsonSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(map_deserialize_error)?;
    deserializer
        .end()
        .map_err(|_| ConformanceError::InvalidJson)?;
    Ok(())
}

struct StrictJsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_JSON_NESTING_DEPTH {
            return Err(serde::de::Error::custom("json_nesting_limit_exceeded"));
        }
        deserializer.deserialize_any(StrictJsonVisitor { depth: self.depth })
    }
}

struct StrictJsonVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("strict JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictJsonSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("json_nesting_limit_exceeded"))?;
        while access
            .next_element_seed(StrictJsonSeed { depth })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| serde::de::Error::custom("json_nesting_limit_exceeded"))?;
        let mut keys = BTreeSet::new();
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate_json_key"));
            }
            access.next_value_seed(StrictJsonSeed { depth })?;
        }
        Ok(())
    }
}

fn map_deserialize_error(error: serde_json::Error) -> ConformanceError {
    let message = error.to_string();
    if message.contains("duplicate_json_key") {
        return ConformanceError::DuplicateJsonKey;
    }
    if message.contains("json_nesting_limit_exceeded") {
        return ConformanceError::JsonNestingLimitExceeded;
    }
    ConformanceError::InvalidJson
}
