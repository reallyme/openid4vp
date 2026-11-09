// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use subtle::{Choice, ConstantTimeEq};

use super::{
    ZkPresentation, ZkPresentationBinding, ZkPresentationProfile, ZkPresentationStageKind,
    MAX_ZK_CIRCUIT_LABEL_BYTES, MAX_ZK_PRESENTATION_DERIVED_CLAIMS,
    MAX_ZK_PRESENTATION_PROOF_BYTES, MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES,
    MAX_ZK_STATEMENT_BYTES, MAX_ZK_STATEMENT_ID_BYTES,
    ZK_COMMON_CREDENTIAL_ROOT_PRESENTATION_STAGE_COUNT, ZK_PRESENTATION_STAGE_COUNT,
    ZK_PRESENTATION_TYPE,
};
use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};

/// Validate the unencrypted OpenID4VP binding carried by a ZK envelope.
///
/// This check does not verify a proof. The injected format verifier must also
/// prove that these exact hashes are authenticated by every applicable public
/// input. Keeping the envelope comparison here rejects cross-session replay
/// before an expensive backend is invoked.
pub fn validate_zk_presentation_binding(
    actual: &ZkPresentationBinding,
    expected: &ZkPresentationBinding,
) -> Result<(), ZkFormatError> {
    let transaction_data_matches = match (
        actual.transaction_data_hash.as_ref(),
        expected.transaction_data_hash.as_ref(),
    ) {
        (Some(actual), Some(expected)) => actual.ct_eq(expected),
        (None, None) => Choice::from(1_u8),
        (Some(_), None) | (None, Some(_)) => Choice::from(0_u8),
    };
    let matches = actual.nonce_hash.ct_eq(&expected.nonce_hash)
        & actual.audience_hash.ct_eq(&expected.audience_hash)
        & transaction_data_matches;
    if !bool::from(matches) {
        return Err(ZkFormatError::new(ZkFormatErrorReason::BindingMismatch));
    }
    Ok(())
}

/// Validate the backend-neutral ZK presentation envelope.
///
/// Proof bytes and public inputs remain opaque at this layer. The checks here
/// enforce the stable OpenID4VP contract that every external ZK adapter must
/// satisfy before cryptographic verification starts.
pub fn validate_zk_presentation_shape(presentation: &ZkPresentation) -> Result<(), ZkFormatError> {
    if presentation.type_ != ZK_PRESENTATION_TYPE
        || !valid_stage_count(presentation.profile, presentation.stages.len())
        || presentation.derived_claims.len() > MAX_ZK_PRESENTATION_DERIVED_CLAIMS
        || all_zero(&presentation.binding.nonce_hash)
        || all_zero(&presentation.binding.audience_hash)
        || presentation
            .binding
            .transaction_data_hash
            .as_ref()
            .is_some_and(|hash| all_zero(hash))
    {
        return Err(invalid_encoding());
    }

    validate_derived_claims(presentation)?;
    validate_stages(presentation)?;
    Ok(())
}

fn validate_derived_claims(presentation: &ZkPresentation) -> Result<(), ZkFormatError> {
    for (index, claim) in presentation.derived_claims.iter().enumerate() {
        if claim.statement_id.is_empty()
            || claim.statement_id.len() > MAX_ZK_STATEMENT_ID_BYTES
            || claim.statement.is_empty()
            || claim.statement.len() > MAX_ZK_STATEMENT_BYTES
            || presentation.derived_claims[..index]
                .iter()
                .any(|previous| previous.statement_id == claim.statement_id)
        {
            return Err(invalid_encoding());
        }
    }
    Ok(())
}

fn validate_stages(presentation: &ZkPresentation) -> Result<(), ZkFormatError> {
    for (index, stage) in presentation.stages.iter().enumerate() {
        let expected_kind =
            canonical_stage(presentation.profile, index).ok_or_else(invalid_encoding)?;
        let expected_stage_name = stage_name(presentation.profile, expected_kind);
        let circuit_ref = &stage.circuit_ref;
        if stage.stage != expected_kind
            || stage.proof.is_empty()
            || stage.proof.len() > MAX_ZK_PRESENTATION_PROOF_BYTES
            || stage.public_inputs.is_empty()
            || stage.public_inputs.len() > MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES
            || circuit_ref.stage != expected_stage_name
            || circuit_ref.version == 0
            || invalid_label(&circuit_ref.hash_strategy)
            || invalid_label(&circuit_ref.family)
            || invalid_label(&circuit_ref.stage)
            || all_zero(&stage.artifact_manifest_sha256)
        {
            return Err(invalid_encoding());
        }
    }
    Ok(())
}

const fn expected_stage_count(profile: ZkPresentationProfile) -> usize {
    match profile {
        ZkPresentationProfile::CredentialSubjectClaimV1
        | ZkPresentationProfile::PrivatePersonaClaimV1 => ZK_PRESENTATION_STAGE_COUNT,
        ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1
        | ZkPresentationProfile::CommonCredentialRootPublicPersonaV1 => {
            ZK_COMMON_CREDENTIAL_ROOT_PRESENTATION_STAGE_COUNT
        }
    }
}

const fn valid_stage_count(profile: ZkPresentationProfile, count: usize) -> bool {
    match profile {
        ZkPresentationProfile::CredentialSubjectClaimV1
        | ZkPresentationProfile::PrivatePersonaClaimV1 => {
            // The format parser admits historical four-stage data so the
            // verifier can return a typed unsupported result. It grants no
            // claim without the issuer-status fifth proof.
            count == ZK_PRESENTATION_STAGE_COUNT || count == 4
        }
        _ => count == expected_stage_count(profile),
    }
}

const fn canonical_stage(
    profile: ZkPresentationProfile,
    index: usize,
) -> Option<ZkPresentationStageKind> {
    match profile {
        ZkPresentationProfile::CredentialSubjectClaimV1
        | ZkPresentationProfile::PrivatePersonaClaimV1 => match index {
            0 => Some(ZkPresentationStageKind::Session),
            1 => Some(ZkPresentationStageKind::CredentialEnvelope),
            2 => Some(ZkPresentationStageKind::CredentialRoot),
            3 => Some(ZkPresentationStageKind::Claim),
            4 => Some(ZkPresentationStageKind::IssuerCredentialStatus),
            _ => None,
        },
        ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1
        | ZkPresentationProfile::CommonCredentialRootPublicPersonaV1 => match index {
            0 => Some(ZkPresentationStageKind::RootAttestation),
            1 => Some(ZkPresentationStageKind::RootStatus),
            2 => Some(ZkPresentationStageKind::Lineage0),
            3 => Some(ZkPresentationStageKind::Lineage1),
            4 => Some(ZkPresentationStageKind::SelectedClaim0),
            5 => Some(ZkPresentationStageKind::SelectedClaim1),
            6 => Some(ZkPresentationStageKind::Session),
            7 => Some(ZkPresentationStageKind::IssuerCredentialStatus0),
            8 => Some(ZkPresentationStageKind::IssuerCredentialStatus1),
            _ => None,
        },
    }
}

const fn stage_name(
    profile: ZkPresentationProfile,
    stage: ZkPresentationStageKind,
) -> &'static str {
    match (profile, stage) {
        (
            ZkPresentationProfile::CommonCredentialRootPublicPersonaV1,
            ZkPresentationStageKind::Session,
        ) => "public_session",
        (_, ZkPresentationStageKind::Session) => "session",
        (_, ZkPresentationStageKind::CredentialEnvelope) => "credential_envelope",
        (_, ZkPresentationStageKind::CredentialRoot) => "credential_root",
        (_, ZkPresentationStageKind::Claim) => "claim",
        (_, ZkPresentationStageKind::IssuerCredentialStatus) => "issuer_credential_status",
        (_, ZkPresentationStageKind::RootAttestation) => "root_attestation",
        (_, ZkPresentationStageKind::RootStatus) => "root_status",
        (_, ZkPresentationStageKind::Lineage0 | ZkPresentationStageKind::Lineage1) => "lineage",
        (
            ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1
            | ZkPresentationProfile::CommonCredentialRootPublicPersonaV1,
            ZkPresentationStageKind::IssuerCredentialStatus0
            | ZkPresentationStageKind::IssuerCredentialStatus1,
        ) => "issuer_credential_status",
        (
            ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1,
            ZkPresentationStageKind::SelectedClaim0 | ZkPresentationStageKind::SelectedClaim1,
        ) => "private_persona_claim",
        (
            ZkPresentationProfile::CommonCredentialRootPublicPersonaV1,
            ZkPresentationStageKind::SelectedClaim0 | ZkPresentationStageKind::SelectedClaim1,
        ) => "public_persona_claim",
        _ => "",
    }
}

fn invalid_label(value: &str) -> bool {
    value.is_empty() || value.len() > MAX_ZK_CIRCUIT_LABEL_BYTES
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .fold(0_u8, |accumulator, byte| accumulator | byte)
        == 0
}

const fn invalid_encoding() -> ZkFormatError {
    ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding)
}
