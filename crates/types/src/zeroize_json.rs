// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::Value as JsonValue;
use zeroize::Zeroize;

pub(crate) fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::String(value) => zeroize_sensitive_string(value),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(map) => {
            let old = core::mem::take(map);
            for (mut key, mut value) in old {
                zeroize_sensitive_string(&mut key);
                zeroize_json_value(&mut value);
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
    }
    *value = JsonValue::Null;
}

fn zeroize_sensitive_string(value: &mut String) {
    // The observation branch is eliminated from production builds because
    // `cfg!(test)` is a compile-time constant. Tests use it to verify the
    // actual RAII cleanup paths without retaining sensitive values.
    let observe_test_zeroization = cfg!(test) && value == TEST_ZEROIZE_SENTINEL;
    value.zeroize();
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

pub(crate) const TEST_ZEROIZE_SENTINEL: &str = "transaction-zeroize-sentinel";

std::thread_local! {
    pub(crate) static ZEROIZE_OBSERVATION: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
}
