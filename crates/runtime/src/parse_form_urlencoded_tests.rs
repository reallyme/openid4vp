// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{
    parse_form_urlencoded, parse_form_urlencoded_with_large_value, DEFAULT_MAX_FORM_VALUE_BYTES,
};
use crate::RuntimeErrorReason;

#[test]
fn large_value_requires_an_explicit_named_field() {
    let mut body = b"vp_token=".to_vec();
    body.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_FORM_VALUE_BYTES + 1));
    let default_error = parse_form_urlencoded(&body).expect_err("default cap rejects value");
    assert_eq!(default_error.reason(), RuntimeErrorReason::InvalidFormBody);

    let pairs = parse_form_urlencoded_with_large_value(
        &body,
        Some("vp_token"),
        DEFAULT_MAX_FORM_VALUE_BYTES + 1,
    )
    .expect("named value fits explicit limit");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].value.len(), DEFAULT_MAX_FORM_VALUE_BYTES + 1);
}

#[test]
fn raised_limit_rejects_oversize_and_unrelated_fields() {
    let mut body = b"vp_token=".to_vec();
    body.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_FORM_VALUE_BYTES + 1));
    let oversize = parse_form_urlencoded_with_large_value(
        &body,
        Some("vp_token"),
        DEFAULT_MAX_FORM_VALUE_BYTES,
    )
    .expect_err("named value exceeds its explicit limit");
    assert_eq!(oversize.reason(), RuntimeErrorReason::InvalidFormBody);

    let mut state = b"state=".to_vec();
    state.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_FORM_VALUE_BYTES + 1));
    let unrelated = parse_form_urlencoded_with_large_value(
        &state,
        Some("vp_token"),
        DEFAULT_MAX_FORM_VALUE_BYTES * 2,
    )
    .expect_err("state retains the small cap");
    assert_eq!(unrelated.reason(), RuntimeErrorReason::InvalidFormBody);
}

#[test]
fn encoded_field_name_uses_its_decoded_identity() {
    let mut body = b"vp%5Ftoken=".to_vec();
    body.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_FORM_VALUE_BYTES + 1));
    let pairs = parse_form_urlencoded_with_large_value(
        &body,
        Some("vp_token"),
        DEFAULT_MAX_FORM_VALUE_BYTES + 1,
    )
    .expect("decoded field name receives the named limit");
    assert_eq!(pairs[0].key, "vp_token");
}
