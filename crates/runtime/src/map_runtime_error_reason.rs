// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Maps OpenID4VP runtime errors to local protobuf reason codes.

use buffa::Enumeration;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};

use crate::RuntimeErrorReason;

/// Runtime error reason mapping failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeErrorReasonMappingError {
    /// The protobuf reason does not belong to the runtime error surface.
    #[error("invalid OpenID4VP runtime error reason")]
    InvalidReason,
}

const OPENID4VP_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VP;

/// Convert a runtime error reason into its local protobuf reason.
pub fn runtime_error_reason_to_proto(value: RuntimeErrorReason) -> pb::OpenId4VpErrorReason {
    match value {
        RuntimeErrorReason::MissingField => pb::OpenId4VpErrorReason::RuntimeMissingField,
        RuntimeErrorReason::InvalidProto => pb::OpenId4VpErrorReason::RuntimeInvalidProto,
        RuntimeErrorReason::MissingSigner => pb::OpenId4VpErrorReason::RuntimeMissingSigner,
        RuntimeErrorReason::UnsupportedFeature => {
            pb::OpenId4VpErrorReason::RuntimeUnsupportedFeature
        }
        RuntimeErrorReason::SigningFailed => pb::OpenId4VpErrorReason::RuntimeSigningFailed,
        RuntimeErrorReason::MissingResponseJwtDecryptor => {
            pb::OpenId4VpErrorReason::RuntimeMissingResponseJwtDecryptor
        }
        RuntimeErrorReason::InvalidResponseJwt => {
            pb::OpenId4VpErrorReason::RuntimeInvalidResponseJwt
        }
        RuntimeErrorReason::ResponseJwtDecryptionFailed => {
            pb::OpenId4VpErrorReason::RuntimeResponseJwtDecryptionFailed
        }
        RuntimeErrorReason::ClockUnavailable => pb::OpenId4VpErrorReason::RuntimeClockUnavailable,
        RuntimeErrorReason::RequestObjectNotFound => {
            pb::OpenId4VpErrorReason::RuntimeRequestObjectNotFound
        }
        RuntimeErrorReason::ResponseValidationFailed => {
            pb::OpenId4VpErrorReason::RuntimeResponseValidationFailed
        }
        RuntimeErrorReason::InvalidHttpMethod => pb::OpenId4VpErrorReason::RuntimeInvalidHttpMethod,
        RuntimeErrorReason::InvalidContentType => {
            pb::OpenId4VpErrorReason::RuntimeInvalidContentType
        }
        RuntimeErrorReason::InvalidAcceptHeader => {
            pb::OpenId4VpErrorReason::RuntimeInvalidAcceptHeader
        }
        RuntimeErrorReason::BodyTooLarge => pb::OpenId4VpErrorReason::RuntimeBodyTooLarge,
        RuntimeErrorReason::InvalidFormBody => pb::OpenId4VpErrorReason::RuntimeInvalidFormBody,
        RuntimeErrorReason::MissingFormField => pb::OpenId4VpErrorReason::RuntimeMissingFormField,
        RuntimeErrorReason::DuplicateFormField => {
            pb::OpenId4VpErrorReason::RuntimeDuplicateFormField
        }
        RuntimeErrorReason::WalletNonceMismatch => {
            pb::OpenId4VpErrorReason::RuntimeWalletNonceMismatch
        }
        RuntimeErrorReason::LaunchStoreFailed => pb::OpenId4VpErrorReason::RuntimeLaunchStoreFailed,
        RuntimeErrorReason::LaunchEncodingFailed => {
            pb::OpenId4VpErrorReason::RuntimeLaunchEncodingFailed
        }
        RuntimeErrorReason::MissingVerifiedResponseStore => {
            pb::OpenId4VpErrorReason::RuntimeMissingVerifiedResponseStore
        }
        RuntimeErrorReason::VerifiedResponseStoreFailed => {
            pb::OpenId4VpErrorReason::RuntimeVerifiedResponseStoreFailed
        }
        RuntimeErrorReason::InvalidResponseCode => {
            pb::OpenId4VpErrorReason::RuntimeInvalidResponseCode
        }
        RuntimeErrorReason::SessionConsumeFailed => {
            pb::OpenId4VpErrorReason::RuntimeSessionConsumeFailed
        }
        RuntimeErrorReason::SessionNotFound => pb::OpenId4VpErrorReason::RuntimeSessionNotFound,
        RuntimeErrorReason::SessionAlreadyConsumed => {
            pb::OpenId4VpErrorReason::RuntimeSessionAlreadyConsumed
        }
        RuntimeErrorReason::SessionReservationConflict => {
            pb::OpenId4VpErrorReason::RuntimeSessionReservationConflict
        }
        RuntimeErrorReason::SessionReleaseFailed => {
            pb::OpenId4VpErrorReason::RuntimeSessionReleaseFailed
        }
        RuntimeErrorReason::SessionCommitFailed => {
            pb::OpenId4VpErrorReason::RuntimeSessionCommitFailed
        }
        RuntimeErrorReason::InvalidFollowBackRequirement => {
            pb::OpenId4VpErrorReason::RuntimeInvalidFollowBackRequirement
        }
        RuntimeErrorReason::FollowBackSessionMismatch => {
            pb::OpenId4VpErrorReason::RuntimeFollowBackSessionMismatch
        }
        RuntimeErrorReason::FollowBackExpired => pb::OpenId4VpErrorReason::RuntimeFollowBackExpired,
        RuntimeErrorReason::FollowBackAlreadyRedeemed => {
            pb::OpenId4VpErrorReason::RuntimeFollowBackAlreadyRedeemed
        }
        RuntimeErrorReason::FollowBackRedemptionFailed => {
            pb::OpenId4VpErrorReason::RuntimeFollowBackRedemptionFailed
        }
    }
}

/// Convert a local protobuf reason back to a runtime error reason.
pub fn proto_to_runtime_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<RuntimeErrorReason, RuntimeErrorReasonMappingError> {
    match value {
        pb::OpenId4VpErrorReason::RuntimeMissingField => Ok(RuntimeErrorReason::MissingField),
        pb::OpenId4VpErrorReason::RuntimeInvalidProto => Ok(RuntimeErrorReason::InvalidProto),
        pb::OpenId4VpErrorReason::RuntimeMissingSigner => Ok(RuntimeErrorReason::MissingSigner),
        pb::OpenId4VpErrorReason::RuntimeUnsupportedFeature => {
            Ok(RuntimeErrorReason::UnsupportedFeature)
        }
        pb::OpenId4VpErrorReason::RuntimeSigningFailed => Ok(RuntimeErrorReason::SigningFailed),
        pb::OpenId4VpErrorReason::RuntimeMissingResponseJwtDecryptor => {
            Ok(RuntimeErrorReason::MissingResponseJwtDecryptor)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidResponseJwt => {
            Ok(RuntimeErrorReason::InvalidResponseJwt)
        }
        pb::OpenId4VpErrorReason::RuntimeResponseJwtDecryptionFailed => {
            Ok(RuntimeErrorReason::ResponseJwtDecryptionFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeClockUnavailable => {
            Ok(RuntimeErrorReason::ClockUnavailable)
        }
        pb::OpenId4VpErrorReason::RuntimeRequestObjectNotFound => {
            Ok(RuntimeErrorReason::RequestObjectNotFound)
        }
        pb::OpenId4VpErrorReason::RuntimeResponseValidationFailed => {
            Ok(RuntimeErrorReason::ResponseValidationFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidHttpMethod => {
            Ok(RuntimeErrorReason::InvalidHttpMethod)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidContentType => {
            Ok(RuntimeErrorReason::InvalidContentType)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidAcceptHeader => {
            Ok(RuntimeErrorReason::InvalidAcceptHeader)
        }
        pb::OpenId4VpErrorReason::RuntimeBodyTooLarge => Ok(RuntimeErrorReason::BodyTooLarge),
        pb::OpenId4VpErrorReason::RuntimeInvalidFormBody => Ok(RuntimeErrorReason::InvalidFormBody),
        pb::OpenId4VpErrorReason::RuntimeMissingFormField => {
            Ok(RuntimeErrorReason::MissingFormField)
        }
        pb::OpenId4VpErrorReason::RuntimeDuplicateFormField => {
            Ok(RuntimeErrorReason::DuplicateFormField)
        }
        pb::OpenId4VpErrorReason::RuntimeWalletNonceMismatch => {
            Ok(RuntimeErrorReason::WalletNonceMismatch)
        }
        pb::OpenId4VpErrorReason::RuntimeLaunchStoreFailed => {
            Ok(RuntimeErrorReason::LaunchStoreFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeLaunchEncodingFailed => {
            Ok(RuntimeErrorReason::LaunchEncodingFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeMissingVerifiedResponseStore => {
            Ok(RuntimeErrorReason::MissingVerifiedResponseStore)
        }
        pb::OpenId4VpErrorReason::RuntimeVerifiedResponseStoreFailed => {
            Ok(RuntimeErrorReason::VerifiedResponseStoreFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidResponseCode => {
            Ok(RuntimeErrorReason::InvalidResponseCode)
        }
        pb::OpenId4VpErrorReason::RuntimeSessionConsumeFailed => {
            Ok(RuntimeErrorReason::SessionConsumeFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeSessionNotFound => Ok(RuntimeErrorReason::SessionNotFound),
        pb::OpenId4VpErrorReason::RuntimeSessionAlreadyConsumed => {
            Ok(RuntimeErrorReason::SessionAlreadyConsumed)
        }
        pb::OpenId4VpErrorReason::RuntimeSessionReservationConflict => {
            Ok(RuntimeErrorReason::SessionReservationConflict)
        }
        pb::OpenId4VpErrorReason::RuntimeSessionReleaseFailed => {
            Ok(RuntimeErrorReason::SessionReleaseFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeSessionCommitFailed => {
            Ok(RuntimeErrorReason::SessionCommitFailed)
        }
        pb::OpenId4VpErrorReason::RuntimeInvalidFollowBackRequirement => {
            Ok(RuntimeErrorReason::InvalidFollowBackRequirement)
        }
        pb::OpenId4VpErrorReason::RuntimeFollowBackSessionMismatch => {
            Ok(RuntimeErrorReason::FollowBackSessionMismatch)
        }
        pb::OpenId4VpErrorReason::RuntimeFollowBackExpired => {
            Ok(RuntimeErrorReason::FollowBackExpired)
        }
        pb::OpenId4VpErrorReason::RuntimeFollowBackAlreadyRedeemed => {
            Ok(RuntimeErrorReason::FollowBackAlreadyRedeemed)
        }
        pb::OpenId4VpErrorReason::RuntimeFollowBackRedemptionFailed => {
            Ok(RuntimeErrorReason::FollowBackRedemptionFailed)
        }
        _ => Err(RuntimeErrorReasonMappingError::InvalidReason),
    }
}

/// Return the stable unsigned reason code for a local OpenID4VP reason.
pub fn error_reason_code(reason: pb::OpenId4VpErrorReason) -> u32 {
    match u32::try_from(reason.to_i32()) {
        Ok(code) => code,
        Err(_) => pb::OpenId4VpErrorReason::Unspecified
            .to_i32()
            .unsigned_abs(),
    }
}

/// Wrap a local runtime reason in the shared identity-stack error envelope.
pub fn identity_stack_error_from_reason(
    reason: RuntimeErrorReason,
    correlation_id: Option<&str>,
) -> IdentityStackError {
    IdentityStackError {
        domain: OPENID4VP_DOMAIN.into(),
        reason_code: error_reason_code(runtime_error_reason_to_proto(reason)),
        correlation_id: correlation_id.map_or_else(String::new, str::to_owned),
        ..IdentityStackError::default()
    }
}

/// Extract a runtime reason from a shared identity-stack error envelope.
pub fn error_reason_from_identity_stack_error(
    error: &IdentityStackError,
) -> Result<RuntimeErrorReason, RuntimeErrorReasonMappingError> {
    if error.domain.as_known() != Some(OPENID4VP_DOMAIN) {
        return Err(RuntimeErrorReasonMappingError::InvalidReason);
    }
    let reason_code = i32::try_from(error.reason_code)
        .map_err(|_| RuntimeErrorReasonMappingError::InvalidReason)?;
    let proto_reason = pb::OpenId4VpErrorReason::from_i32(reason_code)
        .ok_or(RuntimeErrorReasonMappingError::InvalidReason)?;
    proto_to_runtime_error_reason(proto_reason)
}

#[cfg(test)]
#[path = "map_runtime_error_reason_tests.rs"]
mod tests;
