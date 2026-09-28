// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, parse_zk_presentation_value, ZkPresentation,
    ZkPresentationCircuitRef, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind, ZK_PRESENTATION_TYPE,
};

use super::prepare_zk_presentation;
use crate::WalletErrorReason;

#[test]
fn prepares_an_externally_produced_zk_envelope() {
    let value = prepare_zk_presentation(presentation_fixture())
        .expect("valid external envelope is accepted");
    assert!(parse_zk_presentation_value(&value)
        .expect("prepared value parses")
        .is_some());
}

#[test]
fn rejects_an_invalid_external_zk_envelope() {
    let mut presentation = presentation_fixture();
    presentation.stages[0].proof.clear();

    let error = prepare_zk_presentation(presentation)
        .expect_err("empty proof material must fail before response construction");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
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
    .map(|(stage, stage_name)| ZkPresentationStage {
        stage,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: "sha256".to_owned(),
            family: "private_claim_v1".to_owned(),
            stage: stage_name.to_owned(),
            version: 1,
        },
        artifact_manifest_sha256: [3_u8; 32],
        proof: vec![4_u8],
        public_inputs: vec![5_u8],
    })
    .collect();
    ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::PrivateClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding: build_zk_presentation_binding(
            "0123456789abcdef",
            "x509_san_dns:verifier.example",
            None,
        ),
    }
}
