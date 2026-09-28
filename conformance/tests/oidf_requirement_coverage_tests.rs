// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Locks certification module coverage to the exact pinned OIDF suite matrix.

use std::collections::BTreeSet;

use serde_json::Value;

#[test]
fn oidf_certification_matrix_modules_have_local_requirement_evidence() {
    let matrix = parse_json_or_null(include_str!("../oidf/profile-matrix.json"));
    let requirements = parse_json_or_null(include_str!("../requirements/openid4vp.json"));

    let expected_modules = matrix
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|profile| profile.get("expected_groups").and_then(Value::as_array))
        .flatten()
        .filter_map(|group| group.get("modules").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let mapped_modules = requirements
        .get("requirements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|requirement| requirement.get("oidf_modules").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();

    let missing = expected_modules
        .difference(&mapped_modules)
        .copied()
        .collect::<Vec<_>>();
    let obsolete = mapped_modules
        .difference(&expected_modules)
        .copied()
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "OIDF certification modules lack local requirement evidence: {missing:?}"
    );
    assert!(
        obsolete.is_empty(),
        "local requirements map modules outside the pinned OIDF matrix: {obsolete:?}"
    );
}

fn parse_json_or_null(body: &str) -> Value {
    match serde_json::from_str(body) {
        Ok(value) => value,
        Err(_) => Value::Null,
    }
}
