// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::PresentationValue;

use super::{
    build_zk_presentation_binding, encode_zk_presentation_value, is_zk_presentation_value,
    parse_zk_presentation_value, validate_zk_presentation_binding, validate_zk_presentation_shape,
    DerivedClaimStatement, ZkPresentation, ZkPresentationBinding, ZkPresentationCircuitRef,
    ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage, ZkPresentationStageKind,
    MAX_ZK_CIRCUIT_LABEL_BYTES, MAX_ZK_PRESENTATION_DERIVED_CLAIMS,
    MAX_ZK_PRESENTATION_PROOF_BYTES, MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES,
    MAX_ZK_STATEMENT_BYTES, MAX_ZK_STATEMENT_ID_BYTES, ZK_PRESENTATION_TYPE,
};
use crate::ZkFormatErrorReason;

#[test]
fn encodes_and_parses_backend_neutral_zk_envelope() {
    let presentation = presentation_fixture();
    let value = encode_zk_presentation_value(presentation.clone())
        .expect("valid test presentation encodes");

    assert!(is_zk_presentation_value(&value));
    let parsed = parse_zk_presentation_value(&value)
        .expect("encoded presentation parses")
        .expect("encoded presentation has the ZK marker");
    assert_eq!(parsed, presentation);
}

#[test]
fn ignores_non_zk_presentation_values() {
    let compact = PresentationValue::Compact("credential".to_owned());
    let other_json = PresentationValue::Json(serde_json::json!({"type": "other"}));

    assert!(!is_zk_presentation_value(&compact));
    assert!(!is_zk_presentation_value(&other_json));
    assert!(parse_zk_presentation_value(&compact)
        .expect("compact value is not malformed")
        .is_none());
    assert!(parse_zk_presentation_value(&other_json)
        .expect("unmarked JSON is not a ZK envelope")
        .is_none());
}

#[test]
fn rejects_binding_mismatch_before_format_verification() {
    let actual = build_zk_presentation_binding("nonce-a", "verifier.example", Some([7_u8; 32]));
    let expected = build_zk_presentation_binding("nonce-b", "verifier.example", Some([7_u8; 32]));

    let error = validate_zk_presentation_binding(&actual, &expected)
        .expect_err("a different nonce must fail before backend verification");
    assert_eq!(error.reason(), ZkFormatErrorReason::BindingMismatch);
}

#[test]
fn binding_validation_checks_transaction_data_presence() {
    let actual = build_zk_presentation_binding("nonce", "verifier.example", None);
    let expected = build_zk_presentation_binding("nonce", "verifier.example", Some([9_u8; 32]));

    let error = validate_zk_presentation_binding(&actual, &expected)
        .expect_err("omitting transaction binding must fail closed");
    assert_eq!(error.reason(), ZkFormatErrorReason::BindingMismatch);
}

#[test]
fn rejects_noncanonical_stage_order_and_metadata() {
    let mut presentation = presentation_fixture();
    presentation.stages.swap(0, 1);
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].circuit_ref.stage = "claim".to_owned();
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].circuit_ref.version = 0;
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].artifact_manifest_sha256 = [0_u8; 32];
    assert_invalid_encoding(&presentation);
}

#[test]
fn permits_bounded_backend_owned_circuit_identifiers() {
    let mut presentation = presentation_fixture();
    for stage in &mut presentation.stages {
        stage.circuit_ref.hash_strategy = "future_hash_lane".to_owned();
        stage.circuit_ref.family = "future_private_profile".to_owned();
    }

    validate_zk_presentation_shape(&presentation)
        .expect("circuit registries belong to the external verifier adapter");
}

#[test]
fn rejects_missing_oversized_and_empty_proof_material() {
    let mut presentation = presentation_fixture();
    presentation.stages.pop();
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].proof.clear();
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].proof = vec![1_u8; MAX_ZK_PRESENTATION_PROOF_BYTES + 1];
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].public_inputs.clear();
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].public_inputs = vec![1_u8; MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES + 1];
    assert_invalid_encoding(&presentation);
}

#[test]
fn rejects_invalid_derived_claims() {
    let mut presentation = presentation_fixture();
    presentation.derived_claims[0].statement_id.clear();
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.derived_claims[0].statement_id = "x".repeat(MAX_ZK_STATEMENT_ID_BYTES + 1);
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.derived_claims[0].statement = "x".repeat(MAX_ZK_STATEMENT_BYTES + 1);
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation
        .derived_claims
        .push(presentation.derived_claims[0].clone());
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.derived_claims = (0..=MAX_ZK_PRESENTATION_DERIVED_CLAIMS)
        .map(|index| DerivedClaimStatement {
            statement_id: index.to_string(),
            statement: "claim".to_owned(),
        })
        .collect();
    assert_invalid_encoding(&presentation);
}

#[test]
fn rejects_invalid_binding_and_labels() {
    let mut presentation = presentation_fixture();
    presentation.binding.nonce_hash = [0_u8; 32];
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.binding.transaction_data_hash = Some([0_u8; 32]);
    assert_invalid_encoding(&presentation);

    let mut presentation = presentation_fixture();
    presentation.stages[0].circuit_ref.family = "x".repeat(MAX_ZK_CIRCUIT_LABEL_BYTES + 1);
    assert_invalid_encoding(&presentation);
}

#[test]
fn debug_output_redacts_proof_and_binding_material() {
    let presentation = presentation_fixture();
    let debug = format!("{presentation:?}");

    assert!(debug.contains("stage_count: 4"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("proof_len: 3"));
    assert!(!debug.contains("derived-age"));
}

fn assert_invalid_encoding(presentation: &ZkPresentation) {
    let error = validate_zk_presentation_shape(presentation)
        .expect_err("mutated presentation must fail validation");
    assert_eq!(
        error.reason(),
        ZkFormatErrorReason::InvalidPresentationEncoding
    );
}

fn presentation_fixture() -> ZkPresentation {
    let stages = [
        (ZkPresentationStageKind::Session, "session"),
        (
            ZkPresentationStageKind::CredentialEnvelope,
            "credential_envelope",
        ),
        (ZkPresentationStageKind::CredentialRoot, "credential_root"),
        (ZkPresentationStageKind::Claim, "claim"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (stage, stage_name))| ZkPresentationStage {
        stage,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: "sha256".to_owned(),
            family: "private_claim_v1".to_owned(),
            stage: stage_name.to_owned(),
            version: 1,
        },
        artifact_manifest_sha256: [41_u8; 32],
        proof: vec![u8::try_from(index).expect("four stages fit in u8") + 1],
        public_inputs: vec![9_u8, 8_u8, 7_u8],
    })
    .collect();
    ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::PrivateClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: vec![DerivedClaimStatement {
            statement_id: "derived-age".to_owned(),
            statement: "age_over_18".to_owned(),
        }],
        binding: ZkPresentationBinding {
            nonce_hash: [1_u8; 32],
            audience_hash: [2_u8; 32],
            transaction_data_hash: None,
        },
    }
}
