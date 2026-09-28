// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{
    decode_bounded_json, JsonValue, OpenId4VpProtoError, MAX_SENSITIVE_JSON_NESTING_DEPTH,
    ZEROIZE_OBSERVATION,
};

fn reset_zeroize_observation() {
    ZEROIZE_OBSERVATION.with(|observation| observation.set((0, 0)));
}

fn assert_sentinel_was_cleared() {
    ZEROIZE_OBSERVATION.with(|observation| {
        let (observed, cleared) = observation.get();
        assert!(
            observed > 0,
            "the sensitive sentinel reached a zeroizing owner"
        );
        assert_eq!(cleared, observed, "every observed sentinel was cleared");
    });
}

#[test]
fn clears_sensitive_json_after_successful_domain_decode() {
    reset_zeroize_observation();
    let decoded =
        decode_bounded_json::<JsonValue>(br#"{"secret":"sensitive-json-zeroize-sentinel"}"#, 1024)
            .expect("test JSON decodes");
    assert_sentinel_was_cleared();
    drop(decoded);
}

#[test]
fn clears_sensitive_json_on_duplicate_key_failure() {
    reset_zeroize_observation();
    let error = decode_bounded_json::<JsonValue>(
        br#"{"secret":"sensitive-json-zeroize-sentinel","secret":"replacement"}"#,
        1024,
    )
    .expect_err("duplicate keys fail closed");
    assert_eq!(error, OpenId4VpProtoError::JsonDuplicateKey);
    assert_sentinel_was_cleared();
}

#[test]
fn clears_sensitive_json_on_depth_failure() {
    reset_zeroize_observation();
    let mut encoded = String::from(r#"{"secret":"sensitive-json-zeroize-sentinel","nested":"#);
    for _ in 0..=MAX_SENSITIVE_JSON_NESTING_DEPTH {
        encoded.push('[');
    }
    encoded.push_str("null");
    for _ in 0..=MAX_SENSITIVE_JSON_NESTING_DEPTH {
        encoded.push(']');
    }
    encoded.push('}');
    let error = decode_bounded_json::<JsonValue>(encoded.as_bytes(), encoded.len())
        .expect_err("excessive nesting fails closed");
    assert_eq!(error, OpenId4VpProtoError::JsonNestingTooDeep);
    assert_sentinel_was_cleared();
}

#[test]
fn clears_sensitive_json_on_domain_conversion_failure() {
    reset_zeroize_observation();
    let error = decode_bounded_json::<Vec<String>>(
        br#"{"secret":"sensitive-json-zeroize-sentinel"}"#,
        1024,
    )
    .expect_err("a valid JSON tree with the wrong domain shape fails");
    assert_eq!(error, OpenId4VpProtoError::JsonDeserialize);
    assert_sentinel_was_cleared();
}
