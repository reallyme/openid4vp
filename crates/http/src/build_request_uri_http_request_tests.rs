// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::{RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE};
use zeroize::Zeroize;

use crate::build_request_uri_http_request::{
    build_request_uri_http_request, REQUEST_URI_POST_CONTENT_TYPE,
};
use crate::HttpAdapterErrorReason;

#[test]
fn builds_get_request_uri_http_request() {
    let request = build_request_uri_http_request(RequestUriMethod::Get, None)
        .expect("GET request_uri metadata builds");

    assert_eq!(request.accept, REQUEST_OBJECT_MEDIA_TYPE);
    assert_eq!(request.content_type, None);
    assert!(request.body.is_empty());
}

#[test]
fn builds_post_request_uri_http_request_with_encoded_wallet_nonce() {
    let mut request =
        build_request_uri_http_request(RequestUriMethod::Post, Some("nonce with spaces+symbols"))
            .expect("POST request_uri metadata builds");

    assert_eq!(request.accept, REQUEST_OBJECT_MEDIA_TYPE);
    assert_eq!(request.content_type, Some(REQUEST_URI_POST_CONTENT_TYPE));
    assert_eq!(
        request.body,
        b"wallet_nonce=nonce%20with%20spaces%2Bsymbols"
    );

    let debug = format!("{request:?}");
    assert!(!debug.contains("nonce%20with"));
    request.zeroize();
    assert!(request.body.iter().all(|byte| *byte == 0));
}

#[test]
fn builds_post_request_uri_http_request_without_optional_parameters() {
    let request = build_request_uri_http_request(RequestUriMethod::Post, None)
        .expect("POST request_uri permits absent optional parameters");

    assert_eq!(request.accept, REQUEST_OBJECT_MEDIA_TYPE);
    assert_eq!(request.content_type, Some(REQUEST_URI_POST_CONTENT_TYPE));
    assert!(request.body.is_empty());
}

#[test]
fn rejects_explicitly_empty_post_wallet_nonce() {
    let err = build_request_uri_http_request(RequestUriMethod::Post, Some(""))
        .expect_err("an explicitly supplied wallet_nonce must not be empty");

    assert_eq!(err.reason(), HttpAdapterErrorReason::MissingWalletNonce);
}
