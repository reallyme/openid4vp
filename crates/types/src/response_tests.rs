// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::QueryId;

use crate::response::{AuthorizationResponse, PresentationValue};
use crate::{canonical_authorization_response_bytes, OpenId4vpTypeErrorReason};

// Mirrors the codec's public JCS recursion contract; the facade intentionally
// exposes operations rather than its implementation-level limit constant.
const JCS_NESTING_LIMIT: usize = 128;

#[test]
fn serializes_vp_token_as_dcql_keyed_object() {
    let response = AuthorizationResponse::single(
        QueryId::parse("my_credential").expect("test query id is valid"),
        vec![PresentationValue::Compact("eyJhbGci".to_owned())],
        None,
    )
    .expect("test response is valid");

    let json = serde_json::to_value(response).expect("response serializes");
    assert_eq!(json["vp_token"]["my_credential"][0], "eyJhbGci");
}

#[test]
fn deserializes_compact_and_json_presentations_without_untagged_content_buffering() {
    let response: AuthorizationResponse =
        serde_json::from_str(r#"{"vp_token":{"my_credential":["compact",{"given_name":"Ada"}]}}"#)
            .expect("mixed presentation values deserialize");
    let presentations = response
        .vp_token
        .values()
        .next()
        .expect("test response contains one query");

    assert!(matches!(
        presentations.first(),
        Some(PresentationValue::Compact(value)) if value == "compact"
    ));
    assert!(matches!(
        presentations.get(1),
        Some(PresentationValue::Json(value)) if value["given_name"] == "Ada"
    ));
}

#[test]
fn omits_non_standard_response_level_transaction_data_fields() {
    let response = AuthorizationResponse::single(
        QueryId::parse("my_credential").expect("test query id is valid"),
        vec![PresentationValue::Compact("eyJhbGci".to_owned())],
        None,
    )
    .expect("test response is valid");

    let json = serde_json::to_value(response).expect("response serializes");

    assert!(json.get("transaction_data_hashes").is_none());
    assert!(json.get("transaction_data_hashes_alg").is_none());
}

#[test]
fn canonical_response_encoding_is_deterministic() {
    let response = AuthorizationResponse::single(
        QueryId::parse("my_credential").expect("test query id is valid"),
        vec![PresentationValue::Json(serde_json::json!({"z": 1, "a": 2}))],
        Some("opaque-state".to_owned()),
    )
    .expect("test response is valid");

    let bytes = canonical_authorization_response_bytes(&response)
        .expect("typed authorization response canonicalizes");

    assert_eq!(
        bytes.as_slice(),
        br#"{"state":"opaque-state","vp_token":{"my_credential":[{"a":2,"z":1}]}}"#
    );
}

#[test]
fn canonical_response_encoding_rejects_excessive_nesting() {
    let mut nested = serde_json::Value::Null;
    for _ in 0..=JCS_NESTING_LIMIT {
        nested = serde_json::Value::Array(vec![nested]);
    }
    let response = AuthorizationResponse::single(
        QueryId::parse("my_credential").expect("test query id is valid"),
        vec![PresentationValue::Json(nested)],
        None,
    )
    .expect("test response is valid");

    let error = canonical_authorization_response_bytes(&response)
        .expect_err("deeply nested presentation JSON must fail closed");

    assert_eq!(error.reason(), OpenId4vpTypeErrorReason::JsonDepthExceeded);
}
