// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vp_dcql::{CredentialFormat, QueryId};
use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, encode_zk_presentation_value, ZkPresentation,
    ZkPresentationCircuitRef, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_types::{PresentationValue, ResponseMode, TransactionDataHash};
use reallyme_zk_api::{
    ZkArtifactManifestDigest, ZkCommonCredentialRootProofSlot,
    ZkCommonCredentialRootRawPublicInputs, ZkCommonCredentialRootV1Profile, ZkHashStrategy,
    ZkProductionStage, ZkProofBundle, ZkProofBytes, ZkProofProfile, ZkProofSuite, ZkSessionBinding,
    ZkStatusQualifiedBundle,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{WalletAuthorizationRequest, WalletError, WalletErrorReason, WalletInvocationContext};

#[path = "prepare_zk_presentation_helpers.rs"]
pub(crate) mod helpers;

use helpers::{copy_bounded, parse_lower_hex_hash, zk_error};

const MAX_CLAIM_VALUE_BYTES: usize = 64;
const COMMON_CREDENTIAL_ROOT_META_FIELDS: usize = 6;

struct RequestedCommonCredentialRootClaim {
    name_hash: [u8; 32],
    value: Zeroizing<Vec<u8>>,
}

impl Drop for RequestedCommonCredentialRootClaim {
    fn drop(&mut self) {
        self.name_hash.zeroize();
    }
}

impl ZeroizeOnDrop for RequestedCommonCredentialRootClaim {}

/// One validated common-credential-root proof package exposed to the wallet wire adapter.
///
/// The trait keeps OpenID4VP on the proof-system-agnostic `reallyme-zk-api`
/// boundary. Protobuf decoding remains owned by the ZK SDK/proto-codec layer,
/// which can wrap its strict owner type without making the wallet crate parse
/// or trust generated protobuf messages directly.
pub trait WalletCommonCredentialRootProof {
    /// Canonical proof slot.
    fn slot(&self) -> ZkCommonCredentialRootProofSlot;

    /// Artifact manifest identity pinned by this proof package.
    fn artifact_manifest_sha256(&self) -> ZkArtifactManifestDigest;

    /// Bounded proof bytes.
    fn proof_bytes(&self) -> &ZkProofBytes;

    /// Exact raw public inputs for this slot.
    fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs;
}

/// Validated nine-proof common-credential-root presentation exposed to OpenID4VP.
pub trait WalletCommonCredentialRootPresentation {
    /// Concrete proof wrapper type.
    type Proof: WalletCommonCredentialRootProof;

    /// Common-credential-root persona mode.
    fn profile(&self) -> ZkCommonCredentialRootV1Profile;

    /// Shared hash strategy for every proof package.
    fn hash_strategy(&self) -> ZkHashStrategy;

    /// Claimed proof suite.
    fn proof_suite(&self) -> ZkProofSuite;

    /// Request binding authenticated by the common-credential-root session proof.
    fn session_binding(&self) -> ZkSessionBinding;

    /// Proof packages in canonical common-credential-root slot order.
    fn proofs(&self) -> &[Self::Proof];
}

/// Validate an externally produced ZK envelope for inclusion in a response.
///
/// The composed wallet owns credential selection, witness construction, and
/// proof generation. This boundary deliberately accepts only the resulting
/// backend-neutral OpenID4VP envelope.
pub fn prepare_zk_presentation(
    presentation: ZkPresentation,
) -> Result<PresentationValue, WalletError> {
    encode_zk_presentation_value(presentation)
        .map_err(|_| WalletError::new(WalletErrorReason::ZkDerivationFailed))
}

/// Encode an API-owned proof bundle for one authenticated DCQL request.
///
/// The bundle's public inputs must bind the exact verified request nonce,
/// verifier identity, and at most one transaction-data item for this query.
/// Query metadata is checked against the bundle's claimed statement so a
/// wallet cannot accidentally answer a different claim request. The proof is
/// still unverified here; the verifier must check every stage using its own
/// backend and issuer policy.
pub fn prepare_zk_presentation_from_bundle(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    bundle: &ZkProofBundle,
) -> Result<PresentationValue, WalletError> {
    prepare_zk_presentation(build_zk_presentation_from_bundle(
        verified_request,
        invocation,
        query_id,
        bundle,
    )?)
}

/// Encode a direct/private claim together with issuer-signed validity and
/// authenticated current-status evidence for the selected credential.
pub fn prepare_zk_presentation_from_status_qualified_bundle(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    qualified: &ZkStatusQualifiedBundle,
) -> Result<PresentationValue, WalletError> {
    let mut presentation = build_zk_presentation_from_bundle(
        verified_request,
        invocation,
        query_id,
        qualified.claim_bundle(),
    )?;
    let proof = qualified.issuer_credential_status();
    let circuit = proof.public_inputs().circuit_ref();
    presentation
        .stages
        .try_reserve_exact(1)
        .map_err(|_| zk_error())?;
    presentation.stages.push(ZkPresentationStage {
        stage: ZkPresentationStageKind::IssuerCredentialStatus,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: circuit.hash_strategy.as_str().to_owned(),
            family: circuit.family.as_str().to_owned(),
            stage: circuit.stage.as_str().to_owned(),
            version: circuit.version,
        },
        artifact_manifest_sha256: *proof.artifact_manifest_sha256().as_bytes(),
        proof: copy_bounded(proof.proof_bytes().as_bytes())?,
        public_inputs: copy_bounded(proof.public_inputs().as_bytes())?,
    });
    prepare_zk_presentation(presentation)
}

fn build_zk_presentation_from_bundle(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    bundle: &ZkProofBundle,
) -> Result<ZkPresentation, WalletError> {
    let request = verified_request.request();
    let query = request
        .dcql_query
        .credentials
        .iter()
        .find(|candidate| candidate.id == *query_id)
        .ok_or_else(|| WalletError::new(WalletErrorReason::UnknownSelectedCredentialQuery))?;
    if query.format.as_str() != CredentialFormat::REALLYME_ZK_V1
        || !query.require_cryptographic_holder_binding
        || query.claims.is_some()
        || query.claim_sets.is_some()
        || query.trusted_authorities.is_some()
        || bundle.proof_suite() != ZkProofSuite::PRODUCTION
    {
        return Err(zk_error());
    }
    let audience = expected_audience(request, invocation)?;
    let transaction_data_hash = transaction_data_hash_for_query(request, query_id)?;
    let expected = build_zk_presentation_binding(&request.nonce, &audience, transaction_data_hash);
    let binding = bundle.session_binding();
    if binding.nonce_hash != expected.nonce_hash
        || binding.audience_hash != expected.audience_hash
        || binding.transaction_data_hash != expected.transaction_data_hash
    {
        return Err(zk_error());
    }
    let first = bundle.stage_proofs().first().ok_or_else(zk_error)?;
    let hash_strategy = first.proof().circuit_ref().hash_strategy.as_str();
    let statement = bundle.decode_claimed_statement().map_err(|_| zk_error())?;
    validate_query_claim(query, bundle.profile(), hash_strategy, &statement)?;

    let profile = match bundle.profile() {
        ZkProofProfile::CredentialSubjectClaimV1 => ZkPresentationProfile::CredentialSubjectClaimV1,
        ZkProofProfile::PrivatePersonaClaimV1 => ZkPresentationProfile::PrivatePersonaClaimV1,
        _ => return Err(zk_error()),
    };
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkProductionStage::ALL.len())
        .map_err(|_| zk_error())?;
    for stage_proof in bundle.stage_proofs() {
        let stage = match stage_proof.stage() {
            ZkProductionStage::Session => ZkPresentationStageKind::Session,
            ZkProductionStage::CredentialEnvelope => ZkPresentationStageKind::CredentialEnvelope,
            ZkProductionStage::CredentialRoot => ZkPresentationStageKind::CredentialRoot,
            ZkProductionStage::Claim => ZkPresentationStageKind::Claim,
            _ => return Err(zk_error()),
        };
        let proof = stage_proof.proof();
        let circuit = proof.circuit_ref();
        stages.push(ZkPresentationStage {
            stage,
            circuit_ref: ZkPresentationCircuitRef {
                hash_strategy: circuit.hash_strategy.as_str().to_owned(),
                family: circuit.family.as_str().to_owned(),
                stage: circuit.stage.as_str().to_owned(),
                version: circuit.version,
            },
            artifact_manifest_sha256: *proof.artifact_manifest_sha256().as_bytes(),
            proof: copy_bounded(proof.proof_bytes())?,
            public_inputs: copy_bounded(proof.public_inputs().as_bytes())?,
        });
    }
    Ok(ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding: expected,
    })
}

/// Encode a validated common-credential-root presentation for one authenticated DCQL request.
///
/// The supplied presentation owner must already come from the ZK SDK's strict
/// protobuf/domain decoder. This function binds that owner to the active
/// OpenID4VP request and checks the request-owned claim policy metadata before
/// emitting the backend-neutral `vp_token` value.
pub fn prepare_zk_presentation_from_common_credential_root<P>(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    presentation: &P,
) -> Result<PresentationValue, WalletError>
where
    P: WalletCommonCredentialRootPresentation,
{
    let request = verified_request.request();
    let query = request
        .dcql_query
        .credentials
        .iter()
        .find(|candidate| candidate.id == *query_id)
        .ok_or_else(|| WalletError::new(WalletErrorReason::UnknownSelectedCredentialQuery))?;
    if query.format.as_str() != CredentialFormat::REALLYME_ZK_V1
        || !query.require_cryptographic_holder_binding
        || query.claims.is_some()
        || query.claim_sets.is_some()
        || query.trusted_authorities.is_some()
        || presentation.proof_suite() != ZkProofSuite::PRODUCTION
    {
        return Err(zk_error());
    }
    let requested_claims = validate_common_credential_root_query(
        query,
        presentation.profile(),
        presentation.hash_strategy(),
    )?;

    let audience = expected_audience(request, invocation)?;
    let transaction_data_hash = transaction_data_hash_for_query(request, query_id)?;
    let expected = build_zk_presentation_binding(&request.nonce, &audience, transaction_data_hash);
    let binding = presentation.session_binding();
    if binding.nonce_hash != expected.nonce_hash
        || binding.audience_hash != expected.audience_hash
        || binding.transaction_data_hash != expected.transaction_data_hash
    {
        return Err(zk_error());
    }

    let proofs = presentation.proofs();
    if proofs.len() != ZkCommonCredentialRootProofSlot::ALL.len() {
        return Err(zk_error());
    }
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(ZkCommonCredentialRootProofSlot::ALL.len())
        .map_err(|_| zk_error())?;
    for (proof, expected_slot) in proofs
        .iter()
        .zip(ZkCommonCredentialRootProofSlot::ALL.iter())
    {
        if proof.slot() != *expected_slot {
            return Err(zk_error());
        }
        let circuit = proof.public_inputs().circuit_ref();
        if circuit
            != presentation
                .profile()
                .source_ref(presentation.hash_strategy(), *expected_slot)
        {
            return Err(zk_error());
        }
        proof
            .public_inputs()
            .validate_session_binding(binding)
            .map_err(|_| zk_error())?;
        let selected_claim = match expected_slot {
            ZkCommonCredentialRootProofSlot::SelectedClaim0 => Some(&requested_claims[0]),
            ZkCommonCredentialRootProofSlot::SelectedClaim1 => Some(&requested_claims[1]),
            _ => None,
        };
        if let Some(claim) = selected_claim {
            proof
                .public_inputs()
                .validate_claim_disclosure(&claim.name_hash, &claim.value)
                .map_err(|_| zk_error())?;
        }
        stages.push(ZkPresentationStage {
            stage: common_credential_root_stage_kind(*expected_slot)?,
            circuit_ref: ZkPresentationCircuitRef {
                hash_strategy: circuit.hash_strategy.as_str().to_owned(),
                family: circuit.family.as_str().to_owned(),
                stage: circuit.stage.as_str().to_owned(),
                version: circuit.version,
            },
            artifact_manifest_sha256: *proof.artifact_manifest_sha256().as_bytes(),
            proof: copy_bounded(proof.proof_bytes().as_bytes())?,
            public_inputs: copy_bounded(proof.public_inputs().as_bytes())?,
        });
    }

    prepare_zk_presentation(ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: common_credential_root_presentation_profile(presentation.profile())?,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding: expected,
    })
}

pub(crate) fn expected_audience(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
    invocation: &WalletInvocationContext,
) -> Result<String, WalletError> {
    match invocation {
        WalletInvocationContext::ProtocolTransport
            if !matches!(
                request.response_mode,
                Some(ResponseMode::DcApi | ResponseMode::DcApiJwt)
            ) =>
        {
            request
                .client_id
                .as_ref()
                .ok_or_else(zk_error)
                .map(reallyme_openid4vp_types::ClientIdentifier::to_wire_value)
        }
        WalletInvocationContext::DigitalCredentialsApi(origin)
            if matches!(
                request.response_mode,
                Some(ResponseMode::DcApi | ResponseMode::DcApiJwt)
            ) =>
        {
            Ok(["origin:", origin.as_str()].concat())
        }
        _ => Err(zk_error()),
    }
}

fn transaction_data_hash_for_query(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
    query_id: &QueryId,
) -> Result<Option<[u8; 32]>, WalletError> {
    let mut applicable = request
        .transaction_data
        .as_deref()
        .into_iter()
        .flatten()
        .filter(|data| {
            data.credential_ids()
                .iter()
                .any(|id| id == query_id.as_str())
        });
    let transaction_data_hash = applicable
        .next()
        .map(TransactionDataHash::sha256_transaction_data)
        .transpose()
        .map_err(|_| zk_error())?
        .map(|hash| hash.digest);
    if applicable.next().is_some() {
        return Err(zk_error());
    }
    Ok(transaction_data_hash)
}

fn validate_query_claim(
    query: &reallyme_openid4vp_dcql::CredentialQuery,
    profile: ZkProofProfile,
    hash_strategy: &str,
    statement: &reallyme_zk_api::ZkClaimedStatement,
) -> Result<(), WalletError> {
    let meta = &query.meta;
    if !(3..=4).contains(&meta.len())
        || meta.keys().any(|key| {
            !matches!(
                key.as_str(),
                "profile" | "hash_strategy" | "claim_name_hash" | "claim_value_b64u"
            )
        })
        || meta.get("profile").and_then(serde_json::Value::as_str) != Some(profile.as_str())
        || meta
            .get("hash_strategy")
            .and_then(serde_json::Value::as_str)
            != Some(hash_strategy)
    {
        return Err(zk_error());
    }
    let encoded_hash = meta
        .get("claim_name_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(zk_error)?;
    let parsed_hash = parse_lower_hex_hash(encoded_hash).ok_or_else(zk_error)?;
    if !bool::from(parsed_hash.ct_eq(&statement.claim_name_hash())) {
        return Err(zk_error());
    }
    if let Some(encoded) = meta.get("claim_value_b64u") {
        let value = encoded.as_str().ok_or_else(zk_error)?;
        if value.is_empty() || value.len() > 86 {
            return Err(zk_error());
        }
        let decoded = Zeroizing::new(base64url_to_bytes(value).map_err(|_| zk_error())?);
        if decoded.is_empty()
            || decoded.len() > MAX_CLAIM_VALUE_BYTES
            || bytes_to_base64url(&decoded) != value
            || !bool::from(decoded.as_slice().ct_eq(statement.claim_value()))
        {
            return Err(zk_error());
        }
    }
    Ok(())
}

include!("prepare_zk_presentation_common_credential_root.rs");

#[cfg(test)]
#[path = "prepare_zk_presentation_tests.rs"]
mod tests;
