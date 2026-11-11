// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vp_formats::{
    ZkPresentation, ZkPresentationArtifactIdentity, ZkPresentationProfile, ZkPresentationStageKind,
};
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use reallyme_zk_api::{
    artifacts::{ZkArtifactIdentity, ZkArtifactManifestDigest, ZkArtifactSetIdentity},
    circuits::ZkCredentialHashAlgorithm,
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage},
    claim_bundle::{
        ZkClaimProofBundle, ZkClaimProofBundleKind, ZkClaimProofBundleStage,
        ZkClaimProofBundleStageProof,
    },
    common_root::{
        ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProof,
        ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRawPublicInputs,
    },
    issuer_status::ZkIssuerCredentialStatusProof,
    persona_evidence::ZkPersonaCredentialEvidenceMode,
    proofs::{ZkProof, ZkProofBytes, ZkProofSuite, ZkPublicInputs, ZkSessionBinding},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{HolderBindingVerificationContext, VerifierError, VerifierErrorReason};

const CLAIM_NAME_HASH_HEX_BYTES: usize = 64;
const CLAIM_NAME_HASH_BYTES: usize = 32;
const MAX_CLAIM_VALUE_BYTES: usize = 64;
const ZK_QUERY_REQUIRED_META_FIELDS: usize = 3;
const COMMON_CREDENTIAL_ROOT_QUERY_REQUIRED_META_FIELDS: usize = 6;
const PREPARED_QUERY_REQUIRED_META_FIELDS: usize = 4;

pub(super) struct ZkPersonaCredentialEvidenceQueryPolicy {
    pub(super) mode: ZkPersonaCredentialEvidenceMode,
    pub(super) hash_strategy: ZkCredentialHashAlgorithm,
    pub(super) claim_name_hash: [u8; CLAIM_NAME_HASH_BYTES],
    pub(super) claim_value: Zeroizing<Vec<u8>>,
}

impl Drop for ZkPersonaCredentialEvidenceQueryPolicy {
    fn drop(&mut self) {
        self.claim_name_hash.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPersonaCredentialEvidenceQueryPolicy {}

pub(super) fn evidence_mode_from_meta(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Option<ZkPersonaCredentialEvidenceMode> {
    meta.get("profile")
        .and_then(serde_json::Value::as_str)
        .and_then(ZkPersonaCredentialEvidenceMode::from_identifier)
}

pub(super) fn parse_prepared_query_policy(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Result<ZkPersonaCredentialEvidenceQueryPolicy, VerifierError> {
    if meta.len() != PREPARED_QUERY_REQUIRED_META_FIELDS
        || meta.keys().any(|key| {
            !matches!(
                key.as_str(),
                "profile" | "hash_strategy" | "claim_name_hash" | "claim_value_b64u"
            )
        })
    {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let profile = evidence_mode_from_meta(meta)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
    Ok(ZkPersonaCredentialEvidenceQueryPolicy {
        mode: profile,
        hash_strategy: parse_hash_strategy(meta)?,
        claim_name_hash: parse_lower_hex_hash(
            meta.get("claim_name_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
        )?,
        claim_value: parse_claim_value(meta, "claim_value_b64u")?,
    })
}

pub(super) struct ZkQueryPolicy {
    pub(super) bundle_kind: ZkClaimProofBundleKind,
    pub(super) presentation_profile: ZkPresentationProfile,
    pub(super) hash_strategy: ZkCredentialHashAlgorithm,
    pub(super) claim_name_hash: [u8; CLAIM_NAME_HASH_BYTES],
    pub(super) claim_value: Option<Zeroizing<Vec<u8>>>,
}

pub(super) struct ZkCommonCredentialRootQueryPolicy {
    pub(super) persona_mode: ZkCommonCredentialRootPersonaMode,
    pub(super) presentation_profile: ZkPresentationProfile,
    pub(super) hash_strategy: ZkCredentialHashAlgorithm,
    pub(super) first_claim_name_hash: [u8; CLAIM_NAME_HASH_BYTES],
    pub(super) second_claim_name_hash: [u8; CLAIM_NAME_HASH_BYTES],
    pub(super) first_claim_value: Zeroizing<Vec<u8>>,
    pub(super) second_claim_value: Zeroizing<Vec<u8>>,
}

impl Drop for ZkQueryPolicy {
    fn drop(&mut self) {
        self.claim_name_hash.zeroize();
    }
}

impl ZeroizeOnDrop for ZkQueryPolicy {}

impl Drop for ZkCommonCredentialRootQueryPolicy {
    fn drop(&mut self) {
        self.first_claim_name_hash.zeroize();
        self.second_claim_name_hash.zeroize();
    }
}

impl ZeroizeOnDrop for ZkCommonCredentialRootQueryPolicy {}

pub(super) fn common_credential_root_persona_mode_from_meta(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Option<ZkCommonCredentialRootPersonaMode> {
    match meta.get("profile").and_then(serde_json::Value::as_str) {
        Some("common_credential_root_v1_private_persona") => {
            Some(ZkCommonCredentialRootPersonaMode::PrivatePersona)
        }
        Some("common_credential_root_v1_public_persona") => {
            Some(ZkCommonCredentialRootPersonaMode::PublicPersona)
        }
        _ => None,
    }
}

fn common_credential_root_presentation_profile(
    profile: ZkCommonCredentialRootPersonaMode,
) -> Result<ZkPresentationProfile, VerifierError> {
    match profile {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            Ok(ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1)
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            Ok(ZkPresentationProfile::CommonCredentialRootPublicPersonaV1)
        }
    }
}

pub(super) fn parse_common_credential_root_query_policy(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Result<ZkCommonCredentialRootQueryPolicy, VerifierError> {
    if meta.len() != COMMON_CREDENTIAL_ROOT_QUERY_REQUIRED_META_FIELDS
        || meta.keys().any(|key| {
            !matches!(
                key.as_str(),
                "profile"
                    | "hash_strategy"
                    | "claim_0_name_hash"
                    | "claim_0_value_b64u"
                    | "claim_1_name_hash"
                    | "claim_1_value_b64u"
            )
        })
    {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let profile = common_credential_root_persona_mode_from_meta(meta)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
    let hash_strategy = parse_hash_strategy(meta)?;
    Ok(ZkCommonCredentialRootQueryPolicy {
        persona_mode: profile,
        presentation_profile: common_credential_root_presentation_profile(profile)?,
        hash_strategy,
        first_claim_name_hash: parse_lower_hex_hash(
            meta.get("claim_0_name_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
        )?,
        second_claim_name_hash: parse_lower_hex_hash(
            meta.get("claim_1_name_hash")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
        )?,
        first_claim_value: parse_claim_value(meta, "claim_0_value_b64u")?,
        second_claim_value: parse_claim_value(meta, "claim_1_value_b64u")?,
    })
}

fn parse_hash_strategy(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Result<ZkCredentialHashAlgorithm, VerifierError> {
    match meta
        .get("hash_strategy")
        .and_then(serde_json::Value::as_str)
    {
        Some("sha256") => Ok(ZkCredentialHashAlgorithm::Sha256),
        Some("poseidon2") => Ok(ZkCredentialHashAlgorithm::Poseidon2),
        _ => Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        )),
    }
}

fn parse_claim_value(
    meta: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Zeroizing<Vec<u8>>, VerifierError> {
    let encoded_value = meta
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
    if encoded_value.len() > 86 || encoded_value.is_empty() {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let decoded = Zeroizing::new(
        base64url_to_bytes(encoded_value)
            .map_err(|_| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
    );
    if decoded.is_empty()
        || decoded.len() > MAX_CLAIM_VALUE_BYTES
        || bytes_to_base64url(&decoded) != encoded_value
    {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    Ok(decoded)
}

pub(super) fn parse_query_policy(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> Result<ZkQueryPolicy, VerifierError> {
    if meta.len() < ZK_QUERY_REQUIRED_META_FIELDS
        || meta.len() > ZK_QUERY_REQUIRED_META_FIELDS + 1
        || meta.keys().any(|key| {
            !matches!(
                key.as_str(),
                "profile" | "hash_strategy" | "claim_name_hash" | "claim_value_b64u"
            )
        })
    {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let (profile, presentation_profile) =
        match meta.get("profile").and_then(serde_json::Value::as_str) {
            Some("credential_subject_claim_v1") => (
                ZkClaimProofBundleKind::CredentialSubjectClaimV1,
                ZkPresentationProfile::CredentialSubjectClaimV1,
            ),
            Some("private_persona_claim_v1") => (
                ZkClaimProofBundleKind::PrivatePersonaClaimV1,
                ZkPresentationProfile::PrivatePersonaClaimV1,
            ),
            _ => {
                return Err(VerifierError::new(
                    VerifierErrorReason::VpTokenQueryMismatch,
                ))
            }
        };
    let hash_strategy = parse_hash_strategy(meta)?;
    let claim_name_hash = parse_lower_hex_hash(
        meta.get("claim_name_hash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
    )?;
    let claim_value = meta
        .get("claim_value_b64u")
        .map(|value| {
            let encoded_value = value
                .as_str()
                .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
            if encoded_value.len() > 86 || encoded_value.is_empty() {
                return Err(VerifierError::new(
                    VerifierErrorReason::VpTokenQueryMismatch,
                ));
            }
            let decoded = Zeroizing::new(
                base64url_to_bytes(encoded_value)
                    .map_err(|_| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?,
            );
            if decoded.is_empty()
                || decoded.len() > MAX_CLAIM_VALUE_BYTES
                || bytes_to_base64url(&decoded) != encoded_value
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::VpTokenQueryMismatch,
                ));
            }
            Ok(decoded)
        })
        .transpose()?;
    Ok(ZkQueryPolicy {
        bundle_kind: profile,
        presentation_profile,
        hash_strategy,
        claim_name_hash,
        claim_value,
    })
}

pub(super) fn parse_lower_hex_hash(
    value: &str,
) -> Result<[u8; CLAIM_NAME_HASH_BYTES], VerifierError> {
    let bytes = value.as_bytes();
    if bytes.len() != CLAIM_NAME_HASH_HEX_BYTES {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let mut hash = [0_u8; CLAIM_NAME_HASH_BYTES];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (output, pair) in hash.iter_mut().zip(pairs) {
        let high = lower_hex_nibble(pair[0])
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
        let low = lower_hex_nibble(pair[1])
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
        *output = (high << 4) | low;
    }
    Ok(hash)
}

const fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(super) fn transaction_data_hash(
    context: HolderBindingVerificationContext<'_>,
) -> Result<Option<[u8; 32]>, VerifierError> {
    let mut bindings = context
        .session()
        .binding
        .transaction_data_bindings
        .iter()
        .filter(|binding| binding.query_id == context.credential_query().id);
    let first = bindings.next();
    if bindings.next().is_some()
        || first.is_some_and(|binding| binding.algorithm != TransactionDataHashAlgorithm::Sha256)
    {
        return Err(invalid_zk());
    }
    Ok(first.map(|binding| binding.digest))
}

pub(super) fn build_common_credential_root_proofs(
    presentation: &ZkPresentation,
    profile: ZkCommonCredentialRootPersonaMode,
    hash_strategy: ZkCredentialHashAlgorithm,
) -> Result<Vec<ZkCommonCredentialRootProof>, VerifierError> {
    let mut proofs = Vec::new();
    proofs
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| invalid_zk())?;
    for (stage, expected_slot) in presentation
        .stages
        .iter()
        .zip(ZkCommonCredentialRootProofSlot::ALL.iter())
    {
        let expected_kind = common_credential_root_stage_kind(*expected_slot)?;
        let circuit_ref = profile.source_ref(hash_strategy, *expected_slot);
        if stage.stage != expected_kind || !stage_matches_circuit(stage, circuit_ref) {
            return Err(invalid_zk());
        }
        let public_inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
            circuit_ref,
            stage.public_inputs.clone(),
        )
        .map_err(|_| invalid_zk())?;
        proofs.push(
            ZkCommonCredentialRootProof::try_from_parts(
                profile,
                *expected_slot,
                ZkProofSuite::PRODUCTION,
                artifact_identity_from_wire(&stage.artifact_identity),
                ZkProofBytes::try_copy_from_slice(&stage.proof).map_err(|_| invalid_zk())?,
                public_inputs,
            )
            .map_err(|_| invalid_zk())?,
        );
    }
    Ok(proofs)
}

include!("zk_holder_binding_query_stage.rs");
