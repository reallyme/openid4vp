// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    error_reason_code, error_reason_from_identity_stack_error, identity_stack_error_from_reason,
    proto_to_runtime_error_reason, runtime_error_reason_to_proto, IdentityStackError,
    IdentityStackErrorDomain, RuntimeErrorReason, RuntimeErrorReasonMappingError, OPENID4VP_DOMAIN,
};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;

#[test]
fn runtime_error_reasons_round_trip_through_proto() -> Result<(), RuntimeErrorReasonMappingError> {
    let cases = [
        (
            RuntimeErrorReason::MissingField,
            pb::OpenId4VpErrorReason::RuntimeMissingField,
        ),
        (
            RuntimeErrorReason::InvalidProto,
            pb::OpenId4VpErrorReason::RuntimeInvalidProto,
        ),
        (
            RuntimeErrorReason::MissingSigner,
            pb::OpenId4VpErrorReason::RuntimeMissingSigner,
        ),
        (
            RuntimeErrorReason::UnsupportedFeature,
            pb::OpenId4VpErrorReason::RuntimeUnsupportedFeature,
        ),
        (
            RuntimeErrorReason::SigningFailed,
            pb::OpenId4VpErrorReason::RuntimeSigningFailed,
        ),
        (
            RuntimeErrorReason::MissingResponseJwtDecryptor,
            pb::OpenId4VpErrorReason::RuntimeMissingResponseJwtDecryptor,
        ),
        (
            RuntimeErrorReason::InvalidResponseJwt,
            pb::OpenId4VpErrorReason::RuntimeInvalidResponseJwt,
        ),
        (
            RuntimeErrorReason::ResponseJwtDecryptionFailed,
            pb::OpenId4VpErrorReason::RuntimeResponseJwtDecryptionFailed,
        ),
        (
            RuntimeErrorReason::ClockUnavailable,
            pb::OpenId4VpErrorReason::RuntimeClockUnavailable,
        ),
        (
            RuntimeErrorReason::RequestObjectNotFound,
            pb::OpenId4VpErrorReason::RuntimeRequestObjectNotFound,
        ),
        (
            RuntimeErrorReason::ResponseValidationFailed,
            pb::OpenId4VpErrorReason::RuntimeResponseValidationFailed,
        ),
        (
            RuntimeErrorReason::InvalidHttpMethod,
            pb::OpenId4VpErrorReason::RuntimeInvalidHttpMethod,
        ),
        (
            RuntimeErrorReason::InvalidContentType,
            pb::OpenId4VpErrorReason::RuntimeInvalidContentType,
        ),
        (
            RuntimeErrorReason::InvalidAcceptHeader,
            pb::OpenId4VpErrorReason::RuntimeInvalidAcceptHeader,
        ),
        (
            RuntimeErrorReason::BodyTooLarge,
            pb::OpenId4VpErrorReason::RuntimeBodyTooLarge,
        ),
        (
            RuntimeErrorReason::InvalidFormBody,
            pb::OpenId4VpErrorReason::RuntimeInvalidFormBody,
        ),
        (
            RuntimeErrorReason::MissingFormField,
            pb::OpenId4VpErrorReason::RuntimeMissingFormField,
        ),
        (
            RuntimeErrorReason::DuplicateFormField,
            pb::OpenId4VpErrorReason::RuntimeDuplicateFormField,
        ),
        (
            RuntimeErrorReason::WalletNonceMismatch,
            pb::OpenId4VpErrorReason::RuntimeWalletNonceMismatch,
        ),
        (
            RuntimeErrorReason::LaunchStoreFailed,
            pb::OpenId4VpErrorReason::RuntimeLaunchStoreFailed,
        ),
        (
            RuntimeErrorReason::LaunchEncodingFailed,
            pb::OpenId4VpErrorReason::RuntimeLaunchEncodingFailed,
        ),
        (
            RuntimeErrorReason::MissingVerifiedResponseStore,
            pb::OpenId4VpErrorReason::RuntimeMissingVerifiedResponseStore,
        ),
        (
            RuntimeErrorReason::VerifiedResponseStoreFailed,
            pb::OpenId4VpErrorReason::RuntimeVerifiedResponseStoreFailed,
        ),
        (
            RuntimeErrorReason::InvalidResponseCode,
            pb::OpenId4VpErrorReason::RuntimeInvalidResponseCode,
        ),
        (
            RuntimeErrorReason::SessionConsumeFailed,
            pb::OpenId4VpErrorReason::RuntimeSessionConsumeFailed,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(runtime_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_runtime_error_reason(proto)?, domain);
    }
    Ok(())
}

#[test]
fn identity_stack_error_wraps_runtime_reason() -> Result<(), RuntimeErrorReasonMappingError> {
    let error = identity_stack_error_from_reason(RuntimeErrorReason::InvalidProto, Some("corr-rt"));
    assert_eq!(error.domain.as_known(), Some(OPENID4VP_DOMAIN));
    assert_eq!(
        error.reason_code,
        error_reason_code(pb::OpenId4VpErrorReason::RuntimeInvalidProto)
    );
    assert_eq!(error.correlation_id, "corr-rt");
    assert_eq!(
        error_reason_from_identity_stack_error(&error)?,
        RuntimeErrorReason::InvalidProto
    );

    let wrong_domain = IdentityStackError {
        domain: IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VCI.into(),
        reason_code: error_reason_code(pb::OpenId4VpErrorReason::RuntimeInvalidProto),
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&wrong_domain),
        Err(RuntimeErrorReasonMappingError::InvalidReason)
    );

    let wrong_reason_category = IdentityStackError {
        domain: OPENID4VP_DOMAIN.into(),
        reason_code: error_reason_code(pb::OpenId4VpErrorReason::VerifierUnsupportedFormat),
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&wrong_reason_category),
        Err(RuntimeErrorReasonMappingError::InvalidReason)
    );

    let out_of_range_reason = IdentityStackError {
        domain: OPENID4VP_DOMAIN.into(),
        reason_code: u32::MAX,
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&out_of_range_reason),
        Err(RuntimeErrorReasonMappingError::InvalidReason)
    );
    Ok(())
}
