// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;
use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_formats::{
    ZkPresentation, ZkPresentationArtifactIdentity, ZkPresentationBinding, ZkPresentationProfile,
    ZkPresentationProofSuite, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_response_to_proto, decode_authorization_response, encode_authorization_response,
    OpenId4VpProtoError,
};
use reallyme_openid4vp_types::{AuthorizationResponse, PresentationValue};

use super::zk_presentation_stages;

fn artifact_identity_response(identity: ZkPresentationArtifactIdentity) -> AuthorizationResponse {
    let mut stages = zk_presentation_stages();
    stages[0].artifact_identity = identity;
    let presentation = ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::CredentialSubjectClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding: ZkPresentationBinding {
            nonce_hash: [7; 32],
            audience_hash: [8; 32],
            transaction_data_hash: None,
        },
    };
    AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query is valid"),
        vec![PresentationValue::Json(
            serde_json::to_value(presentation).expect("fixture serializes"),
        )],
        None,
    )
    .expect("test response is valid")
}

#[test]
fn protobuf_preserves_both_artifact_identity_constructions() {
    for identity in [
        ZkPresentationArtifactIdentity::Manifest([10; 32]),
        ZkPresentationArtifactIdentity::ArtifactSet([10; 32]),
    ] {
        let response = artifact_identity_response(identity);
        let wire = encode_authorization_response(&response).expect("tagged identity encodes");
        assert_eq!(
            decode_authorization_response(&wire).expect("tagged identity decodes"),
            response
        );
    }
}

#[test]
fn protobuf_rejects_missing_invalid_and_conflicting_artifact_identities() {
    let response = artifact_identity_response(ZkPresentationArtifactIdentity::Manifest([10; 32]));
    for (manifest, artifact_set, expected) in [
        (Vec::new(), None, OpenId4VpProtoError::MissingField),
        (vec![10; 31], None, OpenId4VpProtoError::InvalidField),
        (
            Vec::new(),
            Some(Vec::new()),
            OpenId4VpProtoError::InvalidField,
        ),
        (
            Vec::new(),
            Some(vec![10; 33]),
            OpenId4VpProtoError::InvalidField,
        ),
        (vec![0; 32], None, OpenId4VpProtoError::InvalidField),
        (
            Vec::new(),
            Some(vec![0; 32]),
            OpenId4VpProtoError::InvalidField,
        ),
        (
            vec![10; 32],
            Some(vec![10; 32]),
            OpenId4VpProtoError::InvalidField,
        ),
    ] {
        let mut proto = authorization_response_to_proto(&response).expect("fixture maps");
        let stage = proto
            .vp_token
            .first_mut()
            .and_then(|entry| entry.presentations.first_mut())
            .and_then(|value| value.kind.as_mut())
            .and_then(|kind| match kind {
                pb::presentation_value::Kind::Zk(presentation) => presentation.stages.first_mut(),
                _ => None,
            })
            .expect("fixture has a typed ZK stage");
        stage.artifact_manifest_sha256 = manifest;
        stage.artifact_set_identity_sha256 = artifact_set;
        assert_eq!(
            decode_authorization_response(&proto.encode_to_vec())
                .expect_err("invalid wire identity must fail"),
            expected
        );
    }
}
