#![allow(missing_docs, clippy::unwrap_used)]
// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, EnumValue, Message};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    decode_operation_response_v1, execute_operation_v1, OpenId4VpOperationKind,
    OpenId4VpProtoError, MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
};

fn problem_operation() -> pb::OpenId4VpOperationRequest {
    pb::OpenId4VpOperationRequest {
        contract_version: EnumValue::from(pb::OpenId4VpOperationContractVersion::V1),
        operation: Some(pb::open_id4vp_operation_request::Operation::ProblemDetails(
            Box::new(pb::ProblemDetails {
                r#type: "https://errors.really.me/openid4vp/invalid-request".to_owned(),
                title: "Invalid request".to_owned(),
                status: 400,
                instance: None,
                kind: EnumValue::from(pb::ProblemKind::InvalidRequest),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        __buffa_unknown_fields: Default::default(),
    }
}

#[test]
fn operation_roundtrips_through_the_domain_model() {
    let response_bytes = execute_operation_v1(&problem_operation().encode_to_vec());
    let response = decode_operation_response_v1(
        response_bytes.as_slice(),
        OpenId4VpOperationKind::ProblemDetails,
    )
    .unwrap();

    assert!(matches!(
        response.outcome,
        Some(pb::open_id4vp_operation_response::Outcome::Result(_))
    ));
}

#[test]
fn malformed_oversized_and_unversioned_requests_fail_with_typed_errors() {
    for request in [
        vec![0xff],
        vec![0_u8; MAX_OPENID4VP_PROTO_MESSAGE_BYTES + 1],
        pb::OpenId4VpOperationRequest {
            contract_version: EnumValue::from(pb::OpenId4VpOperationContractVersion::Unspecified),
            operation: problem_operation().operation,
            __buffa_unknown_fields: Default::default(),
        }
        .encode_to_vec(),
    ] {
        let response: pb::OpenId4VpOperationResponse = DecodeOptions::new()
            .decode_from_slice(execute_operation_v1(&request).as_slice())
            .unwrap();
        assert!(matches!(
            response.outcome,
            Some(pb::open_id4vp_operation_response::Outcome::Error(_))
        ));
    }
}

#[test]
fn response_validation_rejects_a_mismatched_result_kind() {
    let response = pb::OpenId4VpOperationResponse {
        outcome: Some(pb::open_id4vp_operation_response::Outcome::Result(
            Box::new(pb::OpenId4VpOperationResult {
                result: Some(
                    pb::open_id4vp_operation_result::Result::AuthorizationResponse(Box::default()),
                ),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        contract_version: EnumValue::from(pb::OpenId4VpOperationContractVersion::V1),
        __buffa_unknown_fields: Default::default(),
    };

    let error = decode_operation_response_v1(
        response.encode_to_vec().as_slice(),
        OpenId4VpOperationKind::ProblemDetails,
    )
    .unwrap_err();
    assert_eq!(error, OpenId4VpProtoError::Decode);
}

#[test]
fn arbitrary_presentation_text_cannot_yield_an_authorization_receipt() {
    let request = pb::OpenId4VpOperationRequest {
        contract_version: EnumValue::from(pb::OpenId4VpOperationContractVersion::V1),
        operation: Some(
            pb::open_id4vp_operation_request::Operation::AuthorizationResponse(Box::new(
                pb::AuthorizationResponse {
                    vp_token: vec![pb::VpTokenEntry {
                        query_id: "pid".to_owned(),
                        presentations: vec![pb::PresentationValue {
                            kind: Some(pb::presentation_value::Kind::Compact(
                                "not-a-signed-presentation".to_owned(),
                            )),
                            __buffa_unknown_fields: Default::default(),
                        }],
                        __buffa_unknown_fields: Default::default(),
                    }],
                    state: None,
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
        __buffa_unknown_fields: Default::default(),
    };

    let response: pb::OpenId4VpOperationResponse = DecodeOptions::new()
        .decode_from_slice(execute_operation_v1(&request.encode_to_vec()).as_slice())
        .unwrap();
    let reason = match response.outcome {
        Some(pb::open_id4vp_operation_response::Outcome::Error(error)) => error.reason.as_known(),
        _ => None,
    };
    assert_eq!(
        reason,
        Some(pb::OpenId4VpErrorReason::RuntimeUnsupportedFeature)
    );
}
