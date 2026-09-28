// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use serde_json::json;

use super::json_values_equal;
use crate::DcqlErrorReason;

#[test]
fn rejects_json_fan_out_before_reserving_beyond_the_work_budget() {
    let expected = json!([null, null]);
    let actual = expected.clone();
    let mut remaining_work = 1;

    let error = json_values_equal(&expected, &actual, &mut remaining_work)
        .expect_err("fan-out larger than the remaining budget must fail before allocation");

    assert_eq!(error.reason(), DcqlErrorReason::QueryTooLarge);
}
