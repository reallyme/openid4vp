// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::{RequestUriMethod, ResponseMode, ResponseType};
use zeroize::Zeroize;

#[test]
fn request_enums_use_final_wire_values() {
    let response_type =
        serde_json::to_value(ResponseType::VpToken).expect("response type serializes");
    let response_mode =
        serde_json::to_value(ResponseMode::DirectPostJwt).expect("response mode serializes");
    let request_uri_method =
        serde_json::to_value(RequestUriMethod::Post).expect("method serializes");

    assert_eq!(response_type, "vp_token");
    assert_eq!(response_mode, "direct_post.jwt");
    assert_eq!(request_uri_method, "post");

    let dc_api: ResponseMode =
        serde_json::from_str("\"dc_api.jwt\"").expect("response mode parses");
    assert_eq!(dc_api, ResponseMode::DcApiJwt);
}

#[test]
fn response_type_rejects_siop_compound_value_without_siop_support() {
    let error = serde_json::from_str::<ResponseType>(r#""vp_token id_token""#)
        .expect_err("the SIOP compound response type must fail closed");

    assert!(error.is_data());
}

#[test]
fn request_object_accepts_scalar_audience() {
    let json = serde_json::json!({
        "response_type": "vp_token",
        "nonce": "0123456789abcdef",
        "dcql_query": {
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {}
            }]
        },
        "aud": "wallet"
    });

    let mut request: super::AuthorizationRequestObject =
        serde_json::from_value(json).expect("scalar aud deserializes");

    assert_eq!(request.aud, Some(vec!["wallet".to_owned()]));
    let debug = format!("{request:?}");
    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("wallet"));
    assert!(debug.contains("<redacted>"));

    request.zeroize();
    assert!(request.nonce.is_empty());
    assert!(request.aud.is_none());
    assert!(request.dcql_query.credentials.is_empty());
}
