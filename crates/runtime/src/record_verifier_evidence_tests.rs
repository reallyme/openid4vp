// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use zeroize::Zeroize;

use crate::VerifierEvidenceContext;

#[test]
fn evidence_context_is_bounded_redacted_and_zeroized() {
    let mut context = VerifierEvidenceContext::new(
        "oid4vp-1final-verifier-haip-test-plan".to_owned(),
        "verifier-sd-jwt-vc-direct-post-jwt".to_owned(),
        "module-instance-1".to_owned(),
        "oid4vp-1final-verifier-happy-flow".to_owned(),
    )
    .expect("test evidence context is valid");

    let debug = format!("{context:?}");
    assert!(!debug.contains("module-instance-1"));
    assert!(!debug.contains("verifier-sd-jwt"));
    assert_eq!(context.module_id(), "module-instance-1");

    context.zeroize();
    assert_eq!(context.plan_id(), "");
    assert_eq!(context.profile_id(), "");
    assert_eq!(context.module_id(), "");
    assert_eq!(context.module_name(), "");
}

#[test]
fn evidence_context_rejects_attacker_controlled_identifiers() {
    assert!(VerifierEvidenceContext::new(
        "profile/unsafe".to_owned(),
        "profile-safe".to_owned(),
        "module-1".to_owned(),
        "module-name".to_owned(),
    )
    .is_err());
    assert!(VerifierEvidenceContext::new(
        "plan-safe".to_owned(),
        "profile-safe".to_owned(),
        "m".repeat(129),
        "module-name".to_owned(),
    )
    .is_err());
    assert!(VerifierEvidenceContext::new(
        "plan-safe".to_owned(),
        "profile-safe".to_owned(),
        "module-1".to_owned(),
        "module\nname".to_owned(),
    )
    .is_err());
}
