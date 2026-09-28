// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_formats::parse_zk_presentation_value;
use reallyme_openid4vp_types::PresentationValue;

fuzz_target!(|data: &[u8]| {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let value = PresentationValue::Json(json);
    let _ = parse_zk_presentation_value(&value);
});
