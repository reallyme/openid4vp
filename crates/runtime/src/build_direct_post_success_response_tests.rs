// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::ResponseCode;
use reallyme_openid4vp_verifier::PostResponseRedirectUri;

use super::direct_post_success_response;

#[test]
fn serializes_optional_redirect_from_the_generated_proto_contract() {
    let redirect = PostResponseRedirectUri::parse(
        "https://verifier.example/oidf/verification-result".to_owned(),
    )
    .expect("test redirect is valid");
    let response_code = ResponseCode::parse("0123456789abcdef012345".to_owned())
        .expect("test response code is valid");
    let with_redirect = direct_post_success_response(Some(&redirect), Some(&response_code))
        .expect("generated response serializes");
    assert_eq!(
        with_redirect.body,
        br#"{"redirect_uri":"https://verifier.example/oidf/verification-result#response_code=0123456789abcdef012345"}"#
    );

    let without_redirect =
        direct_post_success_response(None, None).expect("generated response serializes");
    assert_eq!(without_redirect.body, b"{}");
}

#[test]
fn rejects_non_https_post_response_redirects() {
    assert!(PostResponseRedirectUri::parse("http://verifier.example/result".to_owned()).is_err());
    assert!(
        PostResponseRedirectUri::parse("https://user@verifier.example/result".to_owned()).is_err()
    );
    assert!(
        PostResponseRedirectUri::parse("https://verifier.example/result#fragment".to_owned())
            .is_err()
    );
}

#[test]
fn rejects_incomplete_redirect_and_response_code_pairs() {
    let redirect = PostResponseRedirectUri::parse(
        "https://verifier.example/oidf/verification-result".to_owned(),
    )
    .expect("test redirect is valid");
    let response_code = ResponseCode::parse("0123456789abcdef012345".to_owned())
        .expect("test response code is valid");

    assert!(direct_post_success_response(Some(&redirect), None).is_err());
    let without_redirect = direct_post_success_response(None, Some(&response_code))
        .expect("an omitted redirect produces an empty success body");
    assert_eq!(without_redirect.body, b"{}");
}
