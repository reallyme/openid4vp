// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn common_credential_root_stage_kind(
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<ZkPresentationStageKind, VerifierError> {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => Ok(ZkPresentationStageKind::RootAttestation),
        ZkCommonCredentialRootProofSlot::RootStatus => Ok(ZkPresentationStageKind::RootStatus),
        ZkCommonCredentialRootProofSlot::Lineage0 => Ok(ZkPresentationStageKind::Lineage0),
        ZkCommonCredentialRootProofSlot::Lineage1 => Ok(ZkPresentationStageKind::Lineage1),
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => Ok(ZkPresentationStageKind::SelectedClaim0),
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => Ok(ZkPresentationStageKind::SelectedClaim1),
        ZkCommonCredentialRootProofSlot::Session => Ok(ZkPresentationStageKind::Session),
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus0)
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus1)
        }
        _ => Err(invalid_zk()),
    }
}
fn stage_matches_circuit(
    stage: &reallyme_openid4vp_formats::ZkPresentationStage,
    circuit_ref: ZkCircuitRef,
) -> bool {
    stage.circuit_ref.hash_strategy == circuit_ref.credential_hash_algorithm.as_str()
        && stage.circuit_ref.family == circuit_ref.family.as_str()
        && stage.circuit_ref.stage == circuit_ref.stage.as_str()
        && stage.circuit_ref.version == circuit_ref.revision
        && matches!(
            (circuit_ref.family, circuit_ref.stage),
            (
                ZkCircuitFamily::CommonCredentialRootV1,
                ZkCircuitStage::RootAttestation
            ) | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus)
                | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage)
                | (
                    ZkCircuitFamily::CommonCredentialRootV1,
                    ZkCircuitStage::IssuerCredentialStatus
                )
                | (
                    ZkCircuitFamily::CommonCredentialRootV1,
                    ZkCircuitStage::PrivatePersonaClaim
                )
                | (
                    ZkCircuitFamily::CommonCredentialRootV1,
                    ZkCircuitStage::PublicPersonaClaim
                )
                | (
                    ZkCircuitFamily::PrivatePersonaClaimV1,
                    ZkCircuitStage::Session
                )
                | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PublicSession)
        )
}
pub(super) fn build_bundle(
    presentation: &ZkPresentation,
    profile: ZkClaimProofBundleKind,
    hash_strategy: ZkCredentialHashAlgorithm,
    binding: ZkSessionBinding,
) -> Result<ZkClaimProofBundle, VerifierError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkClaimProofBundleStage::ALL.len())
        .map_err(|_| invalid_zk())?;
    for (stage, expected_stage) in presentation.stages.iter().zip(ZkClaimProofBundleStage::ALL) {
        let expected_kind = match expected_stage {
            ZkClaimProofBundleStage::Session => ZkPresentationStageKind::Session,
            ZkClaimProofBundleStage::CredentialEnvelope => ZkPresentationStageKind::CredentialEnvelope,
            ZkClaimProofBundleStage::CredentialRoot => ZkPresentationStageKind::CredentialRoot,
            ZkClaimProofBundleStage::Claim => ZkPresentationStageKind::Claim,
            _ => return Err(invalid_zk()),
        };
        let circuit_ref = profile.source_ref(hash_strategy, *expected_stage);
        if stage.stage != expected_kind
            || stage.circuit_ref.hash_strategy != circuit_ref.credential_hash_algorithm.as_str()
            || stage.circuit_ref.family != circuit_ref.family.as_str()
            || stage.circuit_ref.stage != circuit_ref.stage.as_str()
            || stage.circuit_ref.version != circuit_ref.revision
        {
            return Err(invalid_zk());
        }
        let proof = ZkProof::try_from_exact_bounded_parts(
            profile.circuit_id(),
            circuit_ref,
            ZkProofSuite::PRODUCTION,
            artifact_identity_from_wire(&stage.artifact_identity),
            ZkProofBytes::try_copy_from_slice(&stage.proof).map_err(|_| invalid_zk())?,
            ZkPublicInputs::try_copy_from_slice(&stage.public_inputs).map_err(|_| invalid_zk())?,
        )
        .map_err(|_| invalid_zk())?;
        proofs.push(
            ZkClaimProofBundleStageProof::try_from_parts(profile, *expected_stage, proof)
                .map_err(|_| invalid_zk())?,
        );
    }
    ZkClaimProofBundle::try_from_stage_proofs(profile, binding, proofs).map_err(|_| invalid_zk())
}
pub(super) fn build_issuer_credential_status_proof(
    presentation: &ZkPresentation,
    hash_strategy: ZkCredentialHashAlgorithm,
) -> Result<ZkIssuerCredentialStatusProof, VerifierError> {
    let stage = presentation
        .stages
        .get(ZkClaimProofBundleStage::ALL.len())
        .ok_or_else(invalid_zk)?;
    let circuit_ref = ZkCircuitRef::new(
        hash_strategy,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    if stage.stage != ZkPresentationStageKind::IssuerCredentialStatus
        || stage.circuit_ref.hash_strategy != circuit_ref.credential_hash_algorithm.as_str()
        || stage.circuit_ref.family != circuit_ref.family.as_str()
        || stage.circuit_ref.stage != circuit_ref.stage.as_str()
        || stage.circuit_ref.version != circuit_ref.revision
    {
        return Err(invalid_zk());
    }
    let public_inputs =
        ZkCommonCredentialRootRawPublicInputs::try_copy_from_slice(circuit_ref, &stage.public_inputs)
            .map_err(|_| invalid_zk())?;
    ZkIssuerCredentialStatusProof::try_from_parts(
        ZkProofSuite::PRODUCTION,
        artifact_identity_from_wire(&stage.artifact_identity)
            .require_artifact_set().map_err(|_| invalid_zk())?,
        ZkProofBytes::try_copy_from_slice(&stage.proof).map_err(|_| invalid_zk())?,
        public_inputs,
    )
    .map_err(|_| invalid_zk())
}

pub(super) const fn invalid_zk() -> VerifierError {
    VerifierError::new(VerifierErrorReason::InvalidZkPresentation)
}

fn artifact_identity_from_wire(identity: &ZkPresentationArtifactIdentity) -> ZkArtifactIdentity {
    match identity {
        ZkPresentationArtifactIdentity::Manifest(digest) =>
            ZkArtifactManifestDigest::from_bytes(*digest).into(),
        ZkPresentationArtifactIdentity::ArtifactSet(digest) =>
            ZkArtifactSetIdentity::from_bytes(*digest).into(),
    }
}
