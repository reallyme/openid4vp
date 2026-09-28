// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::Value as JsonValue;
use zeroize::Zeroize;

pub(crate) fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(value) => value.zeroize(),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(map) => {
            let old = core::mem::take(map);
            for (mut key, mut value) in old {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
    *value = JsonValue::Null;
}
