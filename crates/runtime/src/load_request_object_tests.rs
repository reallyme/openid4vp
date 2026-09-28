// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_verifier::CompactJwt;
use zeroize::Zeroize;

use crate::HostedRequestObject;

#[test]
fn hosted_request_object_redacts_and_zeroizes_values() {
    let jwt = CompactJwt::new("c2Vuc2l0aXZl.aGVhZGVy.c2lnbmF0dXJl".to_owned())
        .expect("fixture request object is valid");
    let mut hosted = HostedRequestObject::signed(jwt);

    let debug = format!("{hosted:?}");
    assert!(!debug.contains("c2Vuc2l0aXZl"));

    hosted.zeroize();
    assert!(matches!(
        &hosted,
        HostedRequestObject::Signed { request_object_jwt } if request_object_jwt.as_str().is_empty()
    ));
}
