// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical versioned operation boundary used by native and Wasm SDKs.

use core::str;

use buffa::{EnumValue, Message};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use zeroize::Zeroizing;

use crate::encode_message::{
    decode_generated_proto, decode_generated_proto_with_limit, encode_generated_proto_with_limit,
};
use crate::map_authorization_request_transport::{
    authorization_request_transport_to_proto, proto_to_authorization_request_transport,
};
use crate::map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
use crate::map_dc_api::{
    digital_credential_request_options_to_proto, proto_to_digital_credential_request_options,
};
use crate::map_error_reason::proto_error_reason_to_proto;
use crate::map_problem_details::{problem_details_to_proto, proto_to_problem_details};
use crate::{
    authorization_request_to_proto, openid4vp_proto_from_json, proto_to_authorization_request,
    OpenId4VpProtoError, MAX_OPENID4VP_PROTO_JSON_BYTES,
};

use pb::open_id4vp_operation_request::Operation as RequestOperation;
use pb::open_id4vp_operation_response::Outcome as ResponseOutcome;
use pb::open_id4vp_operation_result::Result as OperationResult;

/// Maximum protobuf framing added by the versioned response envelope.
pub const MAX_OPENID4VP_OPERATION_RESPONSE_OVERHEAD_BYTES: usize = 32;

/// Maximum accepted output from a composed OpenID4VP platform provider.
pub const MAX_OPENID4VP_OPERATION_RESPONSE_BYTES: usize = 2_097_184;

/// Operation identity expected in untrusted provider output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OpenId4VpOperationKind {
    /// Authorization request structural decoding and normalization.
    AuthorizationRequest,
    /// Reserved Authorization Response operation; authorization is unsupported.
    AuthorizationResponse,
    /// Wallet request-transport structural decoding and normalization.
    AuthorizationRequestTransport,
    /// Digital Credentials API options validation and normalization.
    DigitalCredentialRequestOptions,
    /// RFC 9457 problem-details validation and normalization.
    ProblemDetails,
}

/// Executes a trusted generated request through the canonical domain boundary.
#[must_use]
pub fn execute_operation_request(
    mut request: pb::OpenId4VpOperationRequest,
) -> pb::OpenId4VpOperationResponse {
    if request.contract_version.as_known() != Some(pb::OpenId4VpOperationContractVersion::V1) {
        return error_response(pb::OpenId4VpErrorReason::ProtoInvalidEnumValue);
    }

    // Keep the generated owner alive through normalization so hardened Drop
    // implementations wipe any retained unknown fields after child extraction.
    let Some(operation) = request.operation.take() else {
        return error_response(pb::OpenId4VpErrorReason::ProtoMissingField);
    };

    if matches!(operation, RequestOperation::AuthorizationResponse(_)) {
        // Message shape is not authorization. Verification requires a
        // server-owned session, clock, trust/status adapters, holder-proof
        // verification, and an atomic one-time commit.
        return error_response(pb::OpenId4VpErrorReason::RuntimeUnsupportedFeature);
    }

    match normalize_operation(operation) {
        Ok(result) => result_response(result),
        Err(error) => error_response(proto_error_reason_to_proto(error)),
    }
}

/// Executes bounded binary protobuf input and returns a canonical response.
#[must_use]
pub fn execute_operation_v1(request_bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = match decode_generated_proto(request_bytes) {
        Ok(request) => execute_operation_request(request),
        Err(error) => error_response(proto_error_reason_to_proto(error)),
    };
    encode_response_or_error(response)
}

/// Executes bounded generated ProtoJSON input and returns a binary response.
#[must_use]
pub fn execute_operation_json_v1(request_json: &[u8]) -> Zeroizing<Vec<u8>> {
    let response = if request_json.len() > MAX_OPENID4VP_PROTO_JSON_BYTES {
        error_response(pb::OpenId4VpErrorReason::ProtoJsonTooLarge)
    } else {
        match str::from_utf8(request_json) {
            Ok(json) => match openid4vp_proto_from_json(json) {
                Ok(request) => execute_operation_request(request),
                Err(error) => error_response(proto_error_reason_to_proto(error)),
            },
            Err(_) => error_response(pb::OpenId4VpErrorReason::ProtoJsonDeserialize),
        }
    };
    encode_response_or_error(response)
}

/// Decodes and validates provider output for the submitted operation.
pub fn decode_operation_response_v1(
    bytes: &[u8],
    expected_operation: OpenId4VpOperationKind,
) -> Result<pb::OpenId4VpOperationResponse, OpenId4VpProtoError> {
    let response =
        decode_generated_proto_with_limit(bytes, MAX_OPENID4VP_OPERATION_RESPONSE_BYTES)?;
    validate_response(&response, expected_operation)?;
    Ok(response)
}

fn normalize_operation(
    operation: RequestOperation,
) -> Result<OperationResult, OpenId4VpProtoError> {
    match operation {
        RequestOperation::AuthorizationRequest(value) => {
            let domain = proto_to_authorization_request(&value)?;
            Ok(OperationResult::AuthorizationRequest(Box::new(
                authorization_request_to_proto(&domain)?,
            )))
        }
        RequestOperation::AuthorizationResponse(value) => {
            let domain = proto_to_authorization_response(&value)?;
            Ok(OperationResult::AuthorizationResponse(Box::new(
                authorization_response_to_proto(&domain)?,
            )))
        }
        RequestOperation::AuthorizationRequestTransport(value) => {
            let domain = proto_to_authorization_request_transport(&value)?;
            Ok(OperationResult::AuthorizationRequestTransport(Box::new(
                authorization_request_transport_to_proto(&domain),
            )))
        }
        RequestOperation::DigitalCredentialRequestOptions(value) => {
            let domain = proto_to_digital_credential_request_options(&value)?;
            Ok(OperationResult::DigitalCredentialRequestOptions(Box::new(
                digital_credential_request_options_to_proto(&domain)?,
            )))
        }
        RequestOperation::ProblemDetails(value) => {
            let domain = proto_to_problem_details(&value)?;
            Ok(OperationResult::ProblemDetails(Box::new(
                problem_details_to_proto(&domain),
            )))
        }
    }
}

fn validate_response(
    response: &pb::OpenId4VpOperationResponse,
    expected_operation: OpenId4VpOperationKind,
) -> Result<(), OpenId4VpProtoError> {
    if response.contract_version.as_known() != Some(pb::OpenId4VpOperationContractVersion::V1) {
        return Err(OpenId4VpProtoError::Decode);
    }
    let Some(outcome) = response.outcome.as_ref() else {
        return Err(OpenId4VpProtoError::Decode);
    };
    match outcome {
        ResponseOutcome::Error(error) => match error.reason.as_known() {
            Some(pb::OpenId4VpErrorReason::Unspecified) | None => Err(OpenId4VpProtoError::Decode),
            Some(_) => Ok(()),
        },
        ResponseOutcome::Result(result) => {
            let Some(result) = result.result.as_ref() else {
                return Err(OpenId4VpProtoError::Decode);
            };
            let actual = match result {
                OperationResult::AuthorizationRequest(_) => {
                    OpenId4VpOperationKind::AuthorizationRequest
                }
                OperationResult::AuthorizationResponse(_) => {
                    OpenId4VpOperationKind::AuthorizationResponse
                }
                OperationResult::AuthorizationRequestTransport(_) => {
                    OpenId4VpOperationKind::AuthorizationRequestTransport
                }
                OperationResult::DigitalCredentialRequestOptions(_) => {
                    OpenId4VpOperationKind::DigitalCredentialRequestOptions
                }
                OperationResult::ProblemDetails(_) => OpenId4VpOperationKind::ProblemDetails,
            };
            if actual == expected_operation {
                Ok(())
            } else {
                Err(OpenId4VpProtoError::Decode)
            }
        }
    }
}

fn result_response(result: OperationResult) -> pb::OpenId4VpOperationResponse {
    response_with_outcome(ResponseOutcome::Result(Box::new(
        pb::OpenId4VpOperationResult {
            result: Some(result),
            __buffa_unknown_fields: Default::default(),
        },
    )))
}

fn error_response(reason: pb::OpenId4VpErrorReason) -> pb::OpenId4VpOperationResponse {
    response_with_outcome(ResponseOutcome::Error(Box::new(
        pb::OpenId4VpOperationError {
            reason: EnumValue::from(reason),
            ..Default::default()
        },
    )))
}

fn response_with_outcome(outcome: ResponseOutcome) -> pb::OpenId4VpOperationResponse {
    pb::OpenId4VpOperationResponse {
        outcome: Some(outcome),
        contract_version: EnumValue::from(pb::OpenId4VpOperationContractVersion::V1),
        ..Default::default()
    }
}

fn encode_response_or_error(response: pb::OpenId4VpOperationResponse) -> Zeroizing<Vec<u8>> {
    if let Ok(encoded) =
        encode_generated_proto_with_limit(&response, MAX_OPENID4VP_OPERATION_RESPONSE_BYTES)
    {
        return encoded;
    }

    // The fixed fallback preserves a typed response even if response encoding
    // fails after a successful operation normalization.
    Zeroizing::new(error_response(pb::OpenId4VpErrorReason::ProtoEncode).encode_to_vec())
}
