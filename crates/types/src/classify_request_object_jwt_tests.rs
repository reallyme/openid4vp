// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::{classify_request_object_jwt, OpenId4vpTypeErrorReason, RequestObjectJwtKind};

#[test]
fn classifies_signed_request_object_jwt() {
    let kind =
        classify_request_object_jwt("e30.e30.c2ln").expect("compact JWS is a Request Object");

    assert_eq!(kind, RequestObjectJwtKind::Signed);
}

#[test]
fn classifies_encrypted_request_object_jwt() {
    let kind = classify_request_object_jwt("e30..aXY.Y2lwaGVy.dGFn")
        .expect("compact JWE with direct CEK is a Request Object");

    assert_eq!(kind, RequestObjectJwtKind::Encrypted);
}

#[test]
fn rejects_invalid_request_object_jwt_shape() {
    let err = classify_request_object_jwt("header.payload")
        .expect_err("two segments are not a compact JWS or JWE");

    assert_eq!(
        err.reason(),
        OpenId4vpTypeErrorReason::InvalidRequestObjectJwt
    );
}

#[test]
fn rejects_invalid_request_object_jwt_encoding() {
    let err = classify_request_object_jwt("header.pay+load.signature")
        .expect_err("compact segments must be base64url encoded");

    assert_eq!(
        err.reason(),
        OpenId4vpTypeErrorReason::InvalidRequestObjectJwt
    );
}
