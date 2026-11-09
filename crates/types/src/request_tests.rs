// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::{
    OpenId4vpTypeErrorReason, RequestUriMethod, ResponseMode, ResponseType, VerifierInfoEntry,
    MAX_VERIFIER_INFO_DATA_BYTES,
};
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

#[test]
fn verifier_info_accepts_profile_data_without_claiming_trust() {
    let entry = VerifierInfoEntry::try_new(
        "registration_cert".to_owned(),
        serde_json::json!("signed-registration"),
        None,
    )
    .expect("bounded attestation container");
    assert_eq!(entry.format(), "registration_cert");
    assert_eq!(entry.data(), "signed-registration");
    assert!(entry.credential_ids().is_none());
    assert!(!format!("{entry:?}").contains("signed-registration"));
}

#[test]
fn verifier_info_rejects_empty_oversized_and_duplicate_values() {
    for data in [
        serde_json::json!(null),
        serde_json::json!([]),
        serde_json::json!(""),
    ] {
        let error = VerifierInfoEntry::try_new("jwt".to_owned(), data, None)
            .expect_err("invalid data shape must fail");
        assert_eq!(
            error.reason(),
            OpenId4vpTypeErrorReason::InvalidVerifierInfo
        );
    }
    let oversized = "x".repeat(MAX_VERIFIER_INFO_DATA_BYTES);
    let error = VerifierInfoEntry::try_new("jwt".to_owned(), serde_json::json!(oversized), None)
        .expect_err("oversized attestation must fail");
    assert_eq!(
        error.reason(),
        OpenId4vpTypeErrorReason::InvalidVerifierInfo
    );
    let error = VerifierInfoEntry::try_new(
        "jwt".to_owned(),
        serde_json::json!({"iss": "trusted.example"}),
        Some(vec!["pid".to_owned(), "pid".to_owned()]),
    )
    .expect_err("duplicate query binding must fail");
    assert_eq!(
        error.reason(),
        OpenId4vpTypeErrorReason::InvalidVerifierInfo
    );
}

#[test]
fn verifier_info_rejects_deep_or_excessively_wide_data() {
    let mut deep = serde_json::json!({"leaf": true});
    for _ in 0..=super::MAX_VERIFIER_INFO_JSON_DEPTH {
        deep = serde_json::Value::Array(vec![deep]);
    }
    assert_eq!(
        VerifierInfoEntry::try_new("jwt".to_owned(), deep, None)
            .expect_err("deep attestation data must fail")
            .reason(),
        OpenId4vpTypeErrorReason::InvalidVerifierInfo
    );

    let wide = serde_json::Value::Array(vec![
        serde_json::json!(true);
        super::MAX_VERIFIER_INFO_JSON_NODES
    ]);
    assert_eq!(
        VerifierInfoEntry::try_new("jwt".to_owned(), wide, None)
            .expect_err("wide attestation data must fail")
            .reason(),
        OpenId4vpTypeErrorReason::InvalidVerifierInfo
    );
}
