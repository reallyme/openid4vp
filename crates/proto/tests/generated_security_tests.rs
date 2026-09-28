// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Security contract tests for generated OpenID4VP protobuf bindings.

#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::{Message, MessageField};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1::{
    __buffa::oneof::{
        hosted_request_object::Material as HostedRequestMaterial,
        presentation_value::Kind as PresentationKind,
    },
    AuthorizationRequest, HostedRequestObject, HostedRequestObjectOwnedView, JwsJsonGeneral,
    JwsJsonSignature, PresentationValue, PresentationValueOwnedView, RequestBinding,
    TransactionDataBinding, ZkPresentation, ZkPresentationBinding, ZkPresentationCircuitRef,
    ZkPresentationOwnedView, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind,
};

fn assert_debug_redacts_bytes(debug: String, field_name: &str) {
    assert!(debug.contains(field_name), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("241"), "{debug}");
    assert!(!debug.contains("242"), "{debug}");
    assert!(!debug.contains("243"), "{debug}");
    assert!(!debug.contains("244"), "{debug}");
}

fn assert_debug_omits_sensitive_values(debug: &str) {
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("241"), "{debug}");
    assert!(!debug.contains("242"), "{debug}");
    assert!(!debug.contains("243"), "{debug}");
    assert!(!debug.contains("244"), "{debug}");
    assert!(!debug.contains("sensitive-compact-value"), "{debug}");
}

#[test]
fn generated_zk_presentation_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let presentation = ZkPresentation {
        r#type: "ReallyMeZkPresentation".to_owned(),
        derived_claims: Vec::new(),
        binding: MessageField::some(ZkPresentationBinding {
            nonce_hash: vec![241, 242, 243, 244],
            audience_hash: vec![244, 243, 242, 241],
            transaction_data_hash: Some(vec![242, 243, 244, 241]),
            __buffa_unknown_fields: Default::default(),
        }),
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa.into(),
        profile: ZkPresentationProfile::PrivateClaimV1.into(),
        stages: vec![ZkPresentationStage {
            stage: ZkPresentationStageKind::Session.into(),
            circuit_ref: MessageField::some(ZkPresentationCircuitRef::default()),
            artifact_manifest_sha256: vec![241, 242, 243, 244],
            proof: vec![241, 242, 243, 244],
            public_inputs: vec![244, 243, 242, 241],
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{presentation:?}");
    assert_debug_redacts_bytes(debug.clone(), "proof");
    assert_debug_redacts_bytes(debug, "public_inputs");

    let view = ZkPresentationOwnedView::from_owned(&presentation)?;
    let view_debug = format!("{:?}", view.view());
    assert_debug_omits_sensitive_values(&view_debug);
    assert!(format!("{view:?}").contains("<redacted>"));
    Ok(())
}

#[test]
fn generated_oneof_string_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let presentation = PresentationValue {
        kind: Some(PresentationKind::Compact(
            "sensitive-compact-value".to_owned(),
        )),
        __buffa_unknown_fields: Default::default(),
    };

    assert_debug_omits_sensitive_values(&format!("{presentation:?}"));
    let view = PresentationValueOwnedView::from_owned(&presentation)?;
    assert_debug_omits_sensitive_values(&format!("{:?}", view.view()));
    assert_debug_omits_sensitive_values(&format!("{view:?}"));
    Ok(())
}

#[test]
fn generated_oneof_json_debug_output_is_redacted() -> Result<(), buffa::DecodeError> {
    let presentation = PresentationValue {
        kind: Some(PresentationKind::Json(vec![241, 242, 243, 244])),
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{presentation:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("241"), "{debug}");

    let view = PresentationValueOwnedView::from_owned(&presentation)?;
    let view_debug = format!("{:?}", view.view());
    assert!(view_debug.contains("<redacted>"), "{view_debug}");
    assert!(!view_debug.contains("241"), "{view_debug}");
    Ok(())
}

#[test]
fn generated_proto_json_round_trips_byte_fields() -> Result<(), serde_json::Error> {
    let mut request = AuthorizationRequest::default();
    request.nonce = "0123456789abcdef".to_owned();
    request.dcql_query_json = br#"{"credentials":[]}"#.to_vec();

    let json = serde_json::to_string(&request)?;
    assert!(json.contains("\"dcqlQueryJson\""), "{json}");
    assert!(!json.contains("credentials"), "{json}");

    let decoded: AuthorizationRequest = serde_json::from_str(&json)?;
    assert_eq!(decoded.dcql_query_json, br#"{"credentials":[]}"#);
    Ok(())
}

#[test]
fn generated_proto_json_round_trips_optional_and_repeated_sensitive_strings(
) -> Result<(), serde_json::Error> {
    let mut request = AuthorizationRequest::default();
    request.nonce = "0123456789abcdef".to_owned();
    request.response_uri = Some("https://verifier.example/response".to_owned());
    request.state = Some("fedcba9876543210".to_owned());
    request.expected_origins = vec!["https://wallet.example".to_owned()];
    request.aud = vec!["https://verifier.example".to_owned()];

    let json = serde_json::to_string(&request)?;
    let decoded: AuthorizationRequest = serde_json::from_str(&json)?;

    assert_eq!(decoded.response_uri, request.response_uri);
    assert_eq!(decoded.state, request.state);
    assert_eq!(decoded.expected_origins, request.expected_origins);
    assert_eq!(decoded.aud, request.aud);
    Ok(())
}

#[test]
fn generated_proto_json_round_trips_oneof_bytes() -> Result<(), serde_json::Error> {
    let presentation = PresentationValue {
        kind: Some(PresentationKind::Json(vec![1, 2, 3, 4])),
        __buffa_unknown_fields: Default::default(),
    };

    let json = serde_json::to_string(&presentation)?;
    assert!(json.contains("\"json\""), "{json}");

    let decoded: PresentationValue = serde_json::from_str(&json)?;
    assert_eq!(decoded, presentation);
    Ok(())
}

#[test]
fn generated_proto_json_round_trips_zk_suite_and_manifest_digest() -> Result<(), serde_json::Error>
{
    let presentation = ZkPresentation {
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa.into(),
        profile: ZkPresentationProfile::PrivateClaimV1.into(),
        stages: vec![ZkPresentationStage {
            stage: ZkPresentationStageKind::Session.into(),
            circuit_ref: MessageField::some(ZkPresentationCircuitRef::default()),
            artifact_manifest_sha256: vec![241_u8; 32],
            proof: vec![242_u8; 32],
            public_inputs: vec![243_u8; 32],
            __buffa_unknown_fields: Default::default(),
        }],
        ..Default::default()
    };

    let json = serde_json::to_string(&presentation)?;
    assert!(
        json.contains("ZK_PRESENTATION_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA"),
        "{json}"
    );
    assert!(json.contains("\"artifactManifestSha256\""), "{json}");

    let decoded: ZkPresentation = serde_json::from_str(&json)?;
    assert_eq!(decoded, presentation);
    Ok(())
}

#[test]
fn generated_clear_removes_sensitive_byte_fields() {
    let mut binding = RequestBinding::default();
    binding.transaction_data_bindings = vec![TransactionDataBinding {
        query_id: "pid".to_owned(),
        algorithm: "sha-256".to_owned(),
        digest: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    }];

    binding.clear();
    assert!(binding.transaction_data_bindings.is_empty());
}

#[test]
fn generated_clear_removes_zk_presentation_material() {
    let mut presentation = ZkPresentation {
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa.into(),
        profile: ZkPresentationProfile::PrivateClaimV1.into(),
        stages: vec![ZkPresentationStage {
            stage: ZkPresentationStageKind::Session.into(),
            circuit_ref: MessageField::some(ZkPresentationCircuitRef::default()),
            artifact_manifest_sha256: vec![241_u8; 32],
            proof: vec![241, 242, 243, 244],
            public_inputs: vec![244, 243, 242, 241],
            __buffa_unknown_fields: Default::default(),
        }],
        ..Default::default()
    };

    presentation.clear();

    assert!(presentation.stages.is_empty());
    assert_eq!(
        presentation.proof_suite.as_known(),
        Some(ZkPresentationProofSuite::Unspecified)
    );
    assert_eq!(
        presentation.profile.as_known(),
        Some(ZkPresentationProfile::Unspecified)
    );
}

#[test]
fn generated_clear_removes_sensitive_string_fields() {
    let mut request = AuthorizationRequest::default();
    request.nonce = "0123456789abcdef".to_owned();
    request.state = Some("fedcba9876543210".to_owned());
    request.expected_origins = vec!["https://wallet.example".to_owned()];

    request.clear();

    assert!(request.nonce.is_empty());
    assert!(request.state.is_none());
    assert!(request.expected_origins.is_empty());
}

#[test]
fn generated_multisigned_request_material_is_redacted_and_cleared() {
    let mut request = JwsJsonGeneral {
        payload: "sensitive-payload".to_owned(),
        signatures: vec![JwsJsonSignature {
            protected: "sensitive-protected-header".to_owned(),
            signature: "sensitive-signature".to_owned(),
            __buffa_unknown_fields: Default::default(),
        }],
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("sensitive-payload"), "{debug}");
    assert!(!debug.contains("sensitive-protected-header"), "{debug}");
    assert!(!debug.contains("sensitive-signature"), "{debug}");

    request.clear();
    assert!(request.payload.is_empty());
    assert!(request.signatures.is_empty());
}

#[test]
fn generated_hosted_request_object_material_is_redacted_and_cleared(
) -> Result<(), buffa::DecodeError> {
    let mut request = HostedRequestObject {
        material: Some(HostedRequestMaterial::SignedRequestObjectJwt(
            "sensitive-hosted-request-jwt".to_owned(),
        )),
        __buffa_unknown_fields: Default::default(),
    };

    let debug = format!("{request:?}");
    assert!(debug.contains("<redacted>"), "{debug}");
    assert!(!debug.contains("sensitive-hosted-request-jwt"), "{debug}");
    let view = HostedRequestObjectOwnedView::from_owned(&request)?;
    let view_debug = format!("{:?}", view.view());
    assert!(view_debug.contains("<redacted>"), "{view_debug}");
    assert!(
        !view_debug.contains("sensitive-hosted-request-jwt"),
        "{view_debug}"
    );

    request.clear();
    assert!(request.material.is_none());
    Ok(())
}

#[test]
fn generated_proto_json_rejects_unknown_message_fields() {
    let result = serde_json::from_str::<ZkPresentation>(r#"{"proof":"AQ==","typo":true}"#);

    assert!(
        result.is_err(),
        "unknown generated message fields must fail closed"
    );
    if let Err(error) = result {
        assert!(error.to_string().contains("unknown field"));
    }
}

#[test]
fn generated_proto_json_rejects_unknown_oneof_fields() {
    let result = serde_json::from_str::<PresentationValue>(r#"{"typo":"value"}"#);

    assert!(
        result.is_err(),
        "unknown generated oneof fields must fail closed"
    );
    if let Err(error) = result {
        assert!(error.to_string().contains("unknown field"));
    }
}
