// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroize;

use super::validate_launch_identifier;
use crate::AuthorizationRequestLaunchHttpRequest;

#[test]
fn launch_http_request_redacts_and_zeroizes_values() {
    let mut request = AuthorizationRequestLaunchHttpRequest {
        authorization_endpoint: "https://sensitive.example/authorize".to_owned(),
        module_id: "sensitive-module-id".to_owned(),
        plan_id: "sensitive-plan-id".to_owned(),
        profile_id: "sensitive-profile-id".to_owned(),
        module_name: "sensitive-module-name".to_owned(),
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("sensitive.example"));
    assert!(!debug.contains("sensitive-module-id"));
    assert!(!debug.contains("sensitive-plan-id"));
    assert!(!debug.contains("sensitive-profile-id"));

    request.zeroize();
    assert!(request.authorization_endpoint.is_empty());
    assert!(request.module_id.is_empty());
    assert!(request.plan_id.is_empty());
    assert!(request.profile_id.is_empty());
    assert!(request.module_name.is_empty());
}

#[test]
fn launch_identifiers_reject_unbounded_or_unsafe_values() {
    assert!(validate_launch_identifier("profile-safe_1.0").is_ok());
    assert!(validate_launch_identifier("").is_err());
    assert!(validate_launch_identifier("profile/unsafe").is_err());
    assert!(validate_launch_identifier("prøfile").is_err());
    assert!(validate_launch_identifier(&"a".repeat(129)).is_err());
}
