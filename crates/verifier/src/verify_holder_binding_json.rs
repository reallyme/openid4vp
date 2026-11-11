// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{VerifierError, VerifierErrorReason};

const MAX_VERIFIED_CLAIMS_JSON_BYTES: usize = 256 * 1024;
const MAX_VERIFIED_CLAIMS_DEPTH: usize = 64;

/// Immutable issuer-authenticated JSON claims retained without reparsing.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedJsonClaims {
    value: JsonValue,
}

impl VerifiedJsonClaims {
    /// Retain a format verifier's authenticated disclosure projection.
    pub fn from_authenticated(value: JsonValue) -> Result<Self, VerifierError> {
        // Own the claim tree before any fallible check so rejected projections
        // receive the same zeroization as successfully retained disclosures.
        let claims = Self { value };
        let encoded = reallyme_openid4vp_types::canonical_presentation_json_bytes(&claims.value)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
        if encoded.len() > MAX_VERIFIED_CLAIMS_JSON_BYTES
            || json_depth(&claims.value, 0)? > MAX_VERIFIED_CLAIMS_DEPTH
        {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
        Ok(claims)
    }

    /// Borrow the already-authenticated claim tree.
    #[must_use]
    pub const fn as_value(&self) -> &JsonValue {
        &self.value
    }
}

impl fmt::Debug for VerifiedJsonClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedJsonClaims(<redacted>)")
    }
}

impl Zeroize for VerifiedJsonClaims {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.value);
    }
}

impl Drop for VerifiedJsonClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedJsonClaims {}

fn json_depth(value: &JsonValue, depth: usize) -> Result<usize, VerifierError> {
    if depth > MAX_VERIFIED_CLAIMS_DEPTH {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    let next = depth
        .checked_add(1)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
    match value {
        JsonValue::Array(values) => values.iter().try_fold(depth, |maximum, value| {
            json_depth(value, next).map(|child| maximum.max(child))
        }),
        JsonValue::Object(values) => values.values().try_fold(depth, |maximum, value| {
            json_depth(value, next).map(|child| maximum.max(child))
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            Ok(depth)
        }
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
        JsonValue::String(value) => value.zeroize(),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(values) => {
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
    }
    *value = JsonValue::Null;
}

#[cfg(test)]
#[path = "verify_holder_binding_json_tests.rs"]
mod tests;
