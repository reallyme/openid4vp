// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use buffa::MessageField;
use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_formats::{
    encode_zk_prepared_persona_value, parse_zk_prepared_persona_value, parse_zk_presentation_value,
    validate_zk_presentation_shape, DerivedClaimStatement, ZkPresentation,
    ZkPresentationArtifactIdentity, ZkPresentationBinding, ZkPresentationCircuitRef,
    ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage, ZkPresentationStageKind,
};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{AuthorizationResponse, PresentationValue, VpToken};

use crate::report_proto_error::OpenId4VpProtoError;
use crate::sensitive_json::{
    deserialize_sensitive_json, serialize_sensitive_json, serialize_sensitive_json_value,
    MAX_PRESENTATION_JSON_BYTES,
};

/// Map a Rust AuthorizationResponse into the generated protobuf message.
pub fn authorization_response_to_proto(
    response: &AuthorizationResponse,
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    let vp_token = response
        .vp_token
        .iter()
        .map(|(query_id, presentations)| {
            let presentations = presentations
                .iter()
                .map(presentation_value_to_proto)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(pb::VpTokenEntry {
                query_id: query_id.as_str().to_owned(),
                presentations,
                __buffa_unknown_fields: Default::default(),
            })
        })
        .collect::<Result<Vec<_>, OpenId4VpProtoError>>()?;
    Ok(pb::AuthorizationResponse {
        vp_token,
        state: response.state.clone(),
        __buffa_unknown_fields: Default::default(),
    })
}

/// Map a generated protobuf AuthorizationResponse into the Rust response model.
pub fn proto_to_authorization_response(
    response: &pb::AuthorizationResponse,
) -> Result<AuthorizationResponse, OpenId4VpProtoError> {
    if response.vp_token.is_empty() {
        return Err(OpenId4VpProtoError::MissingField);
    }

    let mut vp_token: VpToken = BTreeMap::new();
    for entry in &response.vp_token {
        let query_id =
            QueryId::parse(&entry.query_id).map_err(|_| OpenId4VpProtoError::InvalidField)?;
        if entry.presentations.is_empty() {
            return Err(OpenId4VpProtoError::MissingField);
        }
        let presentations = entry
            .presentations
            .iter()
            .map(proto_to_presentation_value)
            .collect::<Result<Vec<_>, _>>()?;
        if vp_token.insert(query_id, presentations).is_some() {
            return Err(OpenId4VpProtoError::InvalidField);
        }
    }

    Ok(AuthorizationResponse {
        vp_token,
        state: response.state.clone(),
    })
}

fn presentation_value_to_proto(
    value: &PresentationValue,
) -> Result<pb::PresentationValue, OpenId4VpProtoError> {
    let kind = match value {
        PresentationValue::Compact(value) => {
            Some(pb::presentation_value::Kind::Compact(value.clone()))
        }
        PresentationValue::Json(json) => {
            if let Some(prepared) = parse_zk_prepared_persona_value(value)
                .map_err(|_| OpenId4VpProtoError::InvalidField)?
            {
                return Ok(pb::PresentationValue {
                    kind: Some(pb::presentation_value::Kind::ZkPreparedPersona(
                        prepared.to_vec(),
                    )),
                    __buffa_unknown_fields: Default::default(),
                });
            }
            let presentation = parse_zk_presentation_value(value)
                .map_err(|_| OpenId4VpProtoError::InvalidField)?;
            if let Some(presentation) = presentation {
                return Ok(pb::PresentationValue {
                    kind: Some(pb::presentation_value::Kind::Zk(Box::new(
                        zk_presentation_to_proto(&presentation),
                    ))),
                    __buffa_unknown_fields: Default::default(),
                });
            }
            let bytes = serialize_sensitive_json(json, MAX_PRESENTATION_JSON_BYTES)?;
            Some(pb::presentation_value::Kind::Json(bytes))
        }
    };
    Ok(pb::PresentationValue {
        kind,
        __buffa_unknown_fields: Default::default(),
    })
}

fn proto_to_presentation_value(
    value: &pb::PresentationValue,
) -> Result<PresentationValue, OpenId4VpProtoError> {
    let Some(kind) = value.kind.as_ref() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    match kind {
        pb::presentation_value::Kind::Compact(value) => {
            Ok(PresentationValue::Compact(value.clone()))
        }
        pb::presentation_value::Kind::Json(value) => {
            deserialize_sensitive_json(value, MAX_PRESENTATION_JSON_BYTES)
                .map(PresentationValue::Json)
        }
        pb::presentation_value::Kind::Zk(value) => {
            let presentation = proto_to_zk_presentation(value.as_ref())?;
            serialize_sensitive_json_value(&presentation, MAX_PRESENTATION_JSON_BYTES)
                .map(PresentationValue::Json)
        }
        pb::presentation_value::Kind::ZkPreparedPersona(value) => {
            encode_zk_prepared_persona_value(value).map_err(|_| OpenId4VpProtoError::InvalidField)
        }
    }
}

fn zk_presentation_to_proto(presentation: &ZkPresentation) -> pb::ZkPresentation {
    pb::ZkPresentation {
        r#type: presentation.type_.clone(),
        derived_claims: presentation
            .derived_claims
            .iter()
            .map(derived_claim_statement_to_proto)
            .collect(),
        binding: MessageField::some(zk_presentation_binding_to_proto(&presentation.binding)),
        proof_suite: buffa::EnumValue::from(zk_presentation_proof_suite_to_proto(
            presentation.proof_suite,
        )),
        profile: buffa::EnumValue::from(zk_presentation_profile_to_proto(presentation.profile)),
        stages: presentation
            .stages
            .iter()
            .map(zk_presentation_stage_to_proto)
            .collect(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation(
    presentation: &pb::ZkPresentation,
) -> Result<ZkPresentation, OpenId4VpProtoError> {
    let Some(binding) = presentation.binding.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    let presentation = ZkPresentation {
        type_: presentation.r#type.clone(),
        derived_claims: presentation
            .derived_claims
            .iter()
            .map(proto_to_derived_claim_statement)
            .collect(),
        binding: proto_to_zk_presentation_binding(binding)?,
        proof_suite: proto_to_zk_presentation_proof_suite(&presentation.proof_suite)?,
        profile: proto_to_zk_presentation_profile(&presentation.profile)?,
        stages: presentation
            .stages
            .iter()
            .map(proto_to_zk_presentation_stage)
            .collect::<Result<Vec<_>, _>>()?,
    };
    validate_zk_presentation_shape(&presentation).map_err(|_| OpenId4VpProtoError::InvalidField)?;
    Ok(presentation)
}

fn zk_presentation_profile_to_proto(profile: ZkPresentationProfile) -> pb::ZkPresentationProfile {
    match profile {
        ZkPresentationProfile::CredentialSubjectClaimV1 => {
            pb::ZkPresentationProfile::CredentialSubjectClaimV1
        }
        ZkPresentationProfile::PrivatePersonaClaimV1 => {
            pb::ZkPresentationProfile::PrivatePersonaClaimV1
        }
        ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1 => {
            pb::ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1
        }
        ZkPresentationProfile::CommonCredentialRootPublicPersonaV1 => {
            pb::ZkPresentationProfile::CommonCredentialRootPublicPersonaV1
        }
    }
}

fn proto_to_zk_presentation_profile(
    profile: &buffa::EnumValue<pb::ZkPresentationProfile>,
) -> Result<ZkPresentationProfile, OpenId4VpProtoError> {
    match profile.as_known() {
        Some(pb::ZkPresentationProfile::CredentialSubjectClaimV1) => {
            Ok(ZkPresentationProfile::CredentialSubjectClaimV1)
        }
        Some(pb::ZkPresentationProfile::PrivatePersonaClaimV1) => {
            Ok(ZkPresentationProfile::PrivatePersonaClaimV1)
        }
        Some(pb::ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1) => {
            Ok(ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1)
        }
        Some(pb::ZkPresentationProfile::CommonCredentialRootPublicPersonaV1) => {
            Ok(ZkPresentationProfile::CommonCredentialRootPublicPersonaV1)
        }
        Some(pb::ZkPresentationProfile::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}

fn zk_presentation_stage_to_proto(stage: &ZkPresentationStage) -> pb::ZkPresentationStage {
    let (artifact_manifest_sha256, artifact_set_identity_sha256) = match &stage.artifact_identity {
        ZkPresentationArtifactIdentity::Manifest(digest) => (digest.to_vec(), None),
        ZkPresentationArtifactIdentity::ArtifactSet(digest) => (Vec::new(), Some(digest.to_vec())),
    };
    pb::ZkPresentationStage {
        stage: buffa::EnumValue::from(zk_presentation_stage_kind_to_proto(stage.stage)),
        circuit_ref: MessageField::some(zk_presentation_circuit_ref_to_proto(&stage.circuit_ref)),
        artifact_manifest_sha256,
        artifact_set_identity_sha256,
        proof: stage.proof.clone(),
        public_inputs: stage.public_inputs.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation_stage(
    stage: &pb::ZkPresentationStage,
) -> Result<ZkPresentationStage, OpenId4VpProtoError> {
    let Some(circuit_ref) = stage.circuit_ref.as_option() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    let stage_kind = proto_to_zk_presentation_stage_kind(&stage.stage)?;
    let artifact_identity = match (
        stage.artifact_manifest_sha256.as_slice(),
        stage.artifact_set_identity_sha256.as_deref(),
    ) {
        ([], None) => return Err(OpenId4VpProtoError::MissingField),
        ([], Some(digest)) => {
            ZkPresentationArtifactIdentity::ArtifactSet(hash_bytes_to_array(digest)?)
        }
        (digest, None) => ZkPresentationArtifactIdentity::Manifest(hash_bytes_to_array(digest)?),
        // Choosing one of two supplied digests would let different consumers
        // verify the same stage against different artifact constructions.
        (_, Some(_)) => return Err(OpenId4VpProtoError::InvalidField),
    };
    Ok(ZkPresentationStage {
        stage: stage_kind,
        circuit_ref: proto_to_zk_presentation_circuit_ref(circuit_ref),
        artifact_identity,
        proof: stage.proof.clone(),
        public_inputs: stage.public_inputs.clone(),
    })
}

fn zk_presentation_stage_kind_to_proto(
    stage: ZkPresentationStageKind,
) -> pb::ZkPresentationStageKind {
    match stage {
        ZkPresentationStageKind::Session => pb::ZkPresentationStageKind::Session,
        ZkPresentationStageKind::CredentialEnvelope => {
            pb::ZkPresentationStageKind::CredentialEnvelope
        }
        ZkPresentationStageKind::CredentialRoot => pb::ZkPresentationStageKind::CredentialRoot,
        ZkPresentationStageKind::Claim => pb::ZkPresentationStageKind::Claim,
        ZkPresentationStageKind::RootAttestation => pb::ZkPresentationStageKind::RootAttestation,
        ZkPresentationStageKind::RootStatus => pb::ZkPresentationStageKind::RootStatus,
        ZkPresentationStageKind::Lineage0 => pb::ZkPresentationStageKind::Lineage0,
        ZkPresentationStageKind::Lineage1 => pb::ZkPresentationStageKind::Lineage1,
        ZkPresentationStageKind::SelectedClaim0 => pb::ZkPresentationStageKind::SelectedClaim0,
        ZkPresentationStageKind::SelectedClaim1 => pb::ZkPresentationStageKind::SelectedClaim1,
        ZkPresentationStageKind::IssuerCredentialStatus0 => {
            pb::ZkPresentationStageKind::IssuerCredentialStatus0
        }
        ZkPresentationStageKind::IssuerCredentialStatus1 => {
            pb::ZkPresentationStageKind::IssuerCredentialStatus1
        }
        ZkPresentationStageKind::IssuerCredentialStatus => {
            pb::ZkPresentationStageKind::IssuerCredentialStatus
        }
    }
}

fn proto_to_zk_presentation_stage_kind(
    stage: &buffa::EnumValue<pb::ZkPresentationStageKind>,
) -> Result<ZkPresentationStageKind, OpenId4VpProtoError> {
    match stage.as_known() {
        Some(pb::ZkPresentationStageKind::Session) => Ok(ZkPresentationStageKind::Session),
        Some(pb::ZkPresentationStageKind::CredentialEnvelope) => {
            Ok(ZkPresentationStageKind::CredentialEnvelope)
        }
        Some(pb::ZkPresentationStageKind::CredentialRoot) => {
            Ok(ZkPresentationStageKind::CredentialRoot)
        }
        Some(pb::ZkPresentationStageKind::Claim) => Ok(ZkPresentationStageKind::Claim),
        Some(pb::ZkPresentationStageKind::RootAttestation) => {
            Ok(ZkPresentationStageKind::RootAttestation)
        }
        Some(pb::ZkPresentationStageKind::RootStatus) => Ok(ZkPresentationStageKind::RootStatus),
        Some(pb::ZkPresentationStageKind::Lineage0) => Ok(ZkPresentationStageKind::Lineage0),
        Some(pb::ZkPresentationStageKind::Lineage1) => Ok(ZkPresentationStageKind::Lineage1),
        Some(pb::ZkPresentationStageKind::SelectedClaim0) => {
            Ok(ZkPresentationStageKind::SelectedClaim0)
        }
        Some(pb::ZkPresentationStageKind::SelectedClaim1) => {
            Ok(ZkPresentationStageKind::SelectedClaim1)
        }
        Some(pb::ZkPresentationStageKind::IssuerCredentialStatus0) => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus0)
        }
        Some(pb::ZkPresentationStageKind::IssuerCredentialStatus1) => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus1)
        }
        Some(pb::ZkPresentationStageKind::IssuerCredentialStatus) => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus)
        }
        Some(pb::ZkPresentationStageKind::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}

fn zk_presentation_proof_suite_to_proto(
    suite: ZkPresentationProofSuite,
) -> pb::ZkPresentationProofSuite {
    match suite {
        ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa => {
            pb::ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa
        }
    }
}

fn proto_to_zk_presentation_proof_suite(
    suite: &buffa::EnumValue<pb::ZkPresentationProofSuite>,
) -> Result<ZkPresentationProofSuite, OpenId4VpProtoError> {
    match suite.as_known() {
        Some(pb::ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa) => {
            Ok(ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa)
        }
        Some(pb::ZkPresentationProofSuite::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}

fn derived_claim_statement_to_proto(
    statement: &DerivedClaimStatement,
) -> pb::DerivedClaimStatement {
    pb::DerivedClaimStatement {
        statement_id: statement.statement_id.clone(),
        statement: statement.statement.clone(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_derived_claim_statement(
    statement: &pb::DerivedClaimStatement,
) -> DerivedClaimStatement {
    DerivedClaimStatement {
        statement_id: statement.statement_id.clone(),
        statement: statement.statement.clone(),
    }
}

fn zk_presentation_binding_to_proto(binding: &ZkPresentationBinding) -> pb::ZkPresentationBinding {
    pb::ZkPresentationBinding {
        nonce_hash: binding.nonce_hash.to_vec(),
        audience_hash: binding.audience_hash.to_vec(),
        transaction_data_hash: binding.transaction_data_hash.map(|hash| hash.to_vec()),
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation_binding(
    binding: &pb::ZkPresentationBinding,
) -> Result<ZkPresentationBinding, OpenId4VpProtoError> {
    Ok(ZkPresentationBinding {
        nonce_hash: hash_bytes_to_array(&binding.nonce_hash)?,
        audience_hash: hash_bytes_to_array(&binding.audience_hash)?,
        transaction_data_hash: binding
            .transaction_data_hash
            .as_deref()
            .map(hash_bytes_to_array)
            .transpose()?,
    })
}

fn zk_presentation_circuit_ref_to_proto(
    circuit_ref: &ZkPresentationCircuitRef,
) -> pb::ZkPresentationCircuitRef {
    pb::ZkPresentationCircuitRef {
        hash_strategy: circuit_ref.hash_strategy.clone(),
        family: circuit_ref.family.clone(),
        stage: circuit_ref.stage.clone(),
        version: circuit_ref.version,
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_to_zk_presentation_circuit_ref(
    circuit_ref: &pb::ZkPresentationCircuitRef,
) -> ZkPresentationCircuitRef {
    ZkPresentationCircuitRef {
        hash_strategy: circuit_ref.hash_strategy.clone(),
        family: circuit_ref.family.clone(),
        stage: circuit_ref.stage.clone(),
        version: circuit_ref.version,
    }
}

fn hash_bytes_to_array(value: &[u8]) -> Result<[u8; 32], OpenId4VpProtoError> {
    <[u8; 32]>::try_from(value).map_err(|_| OpenId4VpProtoError::InvalidField)
}
