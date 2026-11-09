// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

//! Independent cases derived from OpenID4VP 1.0 Section 7.1.1. Missing
//! members prune a selection; incompatible container types invalidate it.

use reallyme_openid4vp_dcql::{
    process_json_claims_path, ClaimsPath, ClaimsPathComponent, DcqlErrorReason,
};
use serde_json::json;

#[test]
fn wildcard_prunes_missing_members_without_losing_other_claims() {
    let credential = json!({"entries": [{"value": "first"}, {}, {"value": "last"}]});
    let path = ClaimsPath(vec![
        ClaimsPathComponent::Name("entries".to_owned()),
        ClaimsPathComponent::All,
        ClaimsPathComponent::Name("value".to_owned()),
    ]);
    let selected = process_json_claims_path(&credential, &path).expect("surviving claims");
    assert_eq!(selected.values(), &[&json!("first"), &json!("last")]);
}

#[test]
fn wildcard_prunes_out_of_bounds_arrays_without_losing_other_claims() {
    let credential = json!({"entries": [["first"], [], ["last"]]});
    let path = ClaimsPath(vec![
        ClaimsPathComponent::Name("entries".to_owned()),
        ClaimsPathComponent::All,
        ClaimsPathComponent::Index(0),
    ]);
    let selected = process_json_claims_path(&credential, &path).expect("surviving claims");
    assert_eq!(selected.values(), &[&json!("first"), &json!("last")]);
}

#[test]
fn rejects_wildcard_incompatible_containers_even_when_another_branch_matches() {
    // Silently skipping a type mismatch would turn a malformed credential
    // into an apparently satisfiable query, contrary to Section 7.1.1.
    for (entries, component) in [
        (
            json!([{"value": true}, null]),
            ClaimsPathComponent::Name("value".to_owned()),
        ),
        (json!([[true], false]), ClaimsPathComponent::Index(0)),
        (json!([[true], {}]), ClaimsPathComponent::All),
    ] {
        let credential = json!({"entries": entries});
        let path = ClaimsPath(vec![
            ClaimsPathComponent::Name("entries".to_owned()),
            ClaimsPathComponent::All,
            component,
        ]);
        let error = process_json_claims_path(&credential, &path)
            .expect_err("every selected container must support the next component");
        assert_eq!(error.reason(), DcqlErrorReason::ClaimsPathMismatch);
    }
}

#[test]
fn rejects_wildcard_with_an_empty_final_selection() {
    for entries in [json!([]), json!([{}, {}])] {
        let credential = json!({"entries": entries});
        let path = ClaimsPath(vec![
            ClaimsPathComponent::Name("entries".to_owned()),
            ClaimsPathComponent::All,
            ClaimsPathComponent::Name("value".to_owned()),
        ]);
        let error =
            process_json_claims_path(&credential, &path).expect_err("no claim survives selection");
        assert_eq!(error.reason(), DcqlErrorReason::ClaimsPathMismatch);
    }
}
