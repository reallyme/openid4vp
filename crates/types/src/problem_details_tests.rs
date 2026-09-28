// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::problem_details::{ProblemDetails, ProblemInstance, ProblemKind};

#[test]
fn serializes_rfc9457_shape_without_detail_text() {
    let problem = ProblemDetails::from_kind(ProblemKind::InvalidRequestObject);
    let json = serde_json::to_value(problem).expect("problem details serialize");

    assert_eq!(
        json["type"],
        "https://really.me/problems/invalid-request-object"
    );
    assert_eq!(json["title"], "Invalid request object");
    assert_eq!(json["status"], 400);
    assert_eq!(json["kind"], "InvalidRequestObject");
    assert!(json.get("detail").is_none());
}

#[test]
fn debug_redacts_problem_instance() {
    let problem = ProblemDetails::from_kind(ProblemKind::InvalidRequest)
        .with_instance(ProblemInstance::new("urn:trace:sensitive".to_owned()));

    let debug = format!("{problem:?}");

    assert!(debug.contains("has_instance: true"));
    assert!(!debug.contains("sensitive"));
}
