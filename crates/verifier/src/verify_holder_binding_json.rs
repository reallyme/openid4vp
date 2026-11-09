// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn json_depth(value: &JsonValue, depth: usize) -> Result<usize, VerifierError> {
    if depth > MAX_VERIFIED_CLAIMS_DEPTH {
        return Err(VerifierError::new(
            crate::VerifierErrorReason::InvalidBinding,
        ));
    }
    let next = depth
        .checked_add(1)
        .ok_or_else(|| VerifierError::new(crate::VerifierErrorReason::InvalidBinding))?;
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
