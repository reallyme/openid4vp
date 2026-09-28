// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP proto-backed error reason conversion tests.

use reallyme_openid4vp_dc_api::DcApiErrorReason;
use reallyme_openid4vp_dcql::DcqlErrorReason;
use reallyme_openid4vp_formats::mdoc::MdocFormatErrorReason;
use reallyme_openid4vp_formats::ZkFormatErrorReason;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    dc_api_error_reason_to_proto, dcql_error_reason_to_proto, error_reason_code,
    error_reason_from_i32, error_reason_from_identity_stack_error, error_reason_to_problem_kind,
    identity_stack_error_from_reason, mdoc_error_reason_to_proto, problem_kind_to_error_reason,
    proto_error_reason_to_proto, proto_to_dc_api_error_reason, proto_to_dcql_error_reason,
    proto_to_mdoc_error_reason, proto_to_proto_error_reason, proto_to_type_error_reason,
    proto_to_verifier_error_reason, proto_to_wallet_error_reason, proto_to_zk_error_reason,
    type_error_reason_to_proto, verifier_error_reason_to_proto, wallet_error_reason_to_proto,
    zk_error_reason_to_proto, OpenId4VpProtoError,
};
use reallyme_openid4vp_types::{OpenId4vpTypeErrorReason, ProblemKind};
use reallyme_openid4vp_verifier::VerifierErrorReason;
use reallyme_openid4vp_wallet::WalletErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};

#[test]
fn type_error_reasons_round_trip_through_proto() -> Result<(), OpenId4VpProtoError> {
    let cases = [
        (
            OpenId4vpTypeErrorReason::EmptyValue,
            pb::OpenId4VpErrorReason::TypeEmptyValue,
        ),
        (
            OpenId4vpTypeErrorReason::EmptyCollection,
            pb::OpenId4VpErrorReason::TypeEmptyCollection,
        ),
        (
            OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix,
            pb::OpenId4VpErrorReason::TypeInvalidClientIdentifierPrefix,
        ),
        (
            OpenId4vpTypeErrorReason::UnsupportedMetadataCapability,
            pb::OpenId4VpErrorReason::TypeUnsupportedMetadataCapability,
        ),
        (
            OpenId4vpTypeErrorReason::UnsupportedTransactionDataHashAlgorithm,
            pb::OpenId4VpErrorReason::TypeUnsupportedTransactionDataHashAlgorithm,
        ),
        (
            OpenId4vpTypeErrorReason::InvalidRequestObjectJwt,
            pb::OpenId4VpErrorReason::TypeInvalidRequestObjectJwt,
        ),
        (
            OpenId4vpTypeErrorReason::SerializationFailed,
            pb::OpenId4VpErrorReason::TypeSerializationFailed,
        ),
        (
            OpenId4vpTypeErrorReason::InvalidEncoding,
            pb::OpenId4VpErrorReason::TypeInvalidEncoding,
        ),
        (
            OpenId4vpTypeErrorReason::JsonDepthExceeded,
            pb::OpenId4VpErrorReason::TypeJsonDepthExceeded,
        ),
        (
            OpenId4vpTypeErrorReason::JsonSizeExceeded,
            pb::OpenId4VpErrorReason::TypeJsonSizeExceeded,
        ),
        (
            OpenId4vpTypeErrorReason::DuplicateJsonKey,
            pb::OpenId4VpErrorReason::TypeDuplicateJsonKey,
        ),
        (
            OpenId4vpTypeErrorReason::EmptyPresentationList,
            pb::OpenId4VpErrorReason::TypeEmptyPresentationList,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(type_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_type_error_reason(proto)?, domain);
    }
    Ok(())
}

#[test]
fn problem_kinds_round_trip_through_error_reason_proto() -> Result<(), OpenId4VpProtoError> {
    let cases = [
        (
            ProblemKind::InvalidRequest,
            pb::OpenId4VpErrorReason::ProblemInvalidRequest,
        ),
        (
            ProblemKind::InvalidRequestObject,
            pb::OpenId4VpErrorReason::ProblemInvalidRequestObject,
        ),
        (
            ProblemKind::InvalidClientIdentifier,
            pb::OpenId4VpErrorReason::ProblemInvalidClientIdentifier,
        ),
        (
            ProblemKind::InvalidDcqlQuery,
            pb::OpenId4VpErrorReason::ProblemInvalidDcqlQuery,
        ),
        (
            ProblemKind::UnsatisfiedDcqlQuery,
            pb::OpenId4VpErrorReason::ProblemUnsatisfiedDcqlQuery,
        ),
        (
            ProblemKind::BindingExpired,
            pb::OpenId4VpErrorReason::ProblemBindingExpired,
        ),
        (
            ProblemKind::SessionNotFound,
            pb::OpenId4VpErrorReason::ProblemSessionNotFound,
        ),
        (
            ProblemKind::SessionMismatch,
            pb::OpenId4VpErrorReason::ProblemSessionMismatch,
        ),
        (
            ProblemKind::UnsupportedFeature,
            pb::OpenId4VpErrorReason::ProblemUnsupportedFeature,
        ),
        (
            ProblemKind::WalletUnavailable,
            pb::OpenId4VpErrorReason::ProblemWalletUnavailable,
        ),
        (
            ProblemKind::Internal,
            pb::OpenId4VpErrorReason::ProblemInternal,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(problem_kind_to_error_reason(domain), proto);
        assert_eq!(error_reason_to_problem_kind(proto)?, domain);
    }
    Ok(())
}

#[test]
fn dcql_error_reasons_round_trip_through_proto() -> Result<(), OpenId4VpProtoError> {
    let cases = [
        (
            DcqlErrorReason::InvalidJson,
            pb::OpenId4VpErrorReason::DcqlInvalidJson,
        ),
        (
            DcqlErrorReason::DuplicateJsonKey,
            pb::OpenId4VpErrorReason::DcqlDuplicateJsonKey,
        ),
        (
            DcqlErrorReason::EmptyValue,
            pb::OpenId4VpErrorReason::DcqlEmptyValue,
        ),
        (
            DcqlErrorReason::InvalidIdentifier,
            pb::OpenId4VpErrorReason::DcqlInvalidIdentifier,
        ),
        (
            DcqlErrorReason::DuplicateIdentifier,
            pb::OpenId4VpErrorReason::DcqlDuplicateIdentifier,
        ),
        (
            DcqlErrorReason::ClaimSetsWithoutClaims,
            pb::OpenId4VpErrorReason::DcqlClaimSetsWithoutClaims,
        ),
        (
            DcqlErrorReason::MissingClaimIdentifier,
            pb::OpenId4VpErrorReason::DcqlMissingClaimIdentifier,
        ),
        (
            DcqlErrorReason::UnsupportedTrustedAuthorityType,
            pb::OpenId4VpErrorReason::DcqlUnsupportedTrustedAuthorityType,
        ),
        (
            DcqlErrorReason::UnsupportedClaimProperty,
            pb::OpenId4VpErrorReason::DcqlUnsupportedClaimProperty,
        ),
        (
            DcqlErrorReason::UnknownReference,
            pb::OpenId4VpErrorReason::DcqlUnknownReference,
        ),
        (
            DcqlErrorReason::InvalidClaimsPath,
            pb::OpenId4VpErrorReason::DcqlInvalidClaimsPath,
        ),
        (
            DcqlErrorReason::ClaimsPathMismatch,
            pb::OpenId4VpErrorReason::DcqlClaimsPathMismatch,
        ),
        (
            DcqlErrorReason::InvalidClaimValue,
            pb::OpenId4VpErrorReason::DcqlInvalidClaimValue,
        ),
        (
            DcqlErrorReason::QueryTooLarge,
            pb::OpenId4VpErrorReason::DcqlQueryTooLarge,
        ),
        (
            DcqlErrorReason::InvalidCredentialMetadata,
            pb::OpenId4VpErrorReason::DcqlInvalidCredentialMetadata,
        ),
        (
            DcqlErrorReason::UnsatisfiedRequiredCredential,
            pb::OpenId4VpErrorReason::DcqlUnsatisfiedRequiredCredential,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(dcql_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_dcql_error_reason(proto)?, domain);
    }
    Ok(())
}

#[test]
fn verifier_error_reasons_round_trip_through_proto() -> Result<(), OpenId4VpProtoError> {
    let cases = [
        (
            VerifierErrorReason::InvalidRequestObject,
            pb::OpenId4VpErrorReason::VerifierInvalidRequestObject,
        ),
        (
            VerifierErrorReason::MissingIssuer,
            pb::OpenId4VpErrorReason::VerifierMissingIssuer,
        ),
        (
            VerifierErrorReason::MissingAudience,
            pb::OpenId4VpErrorReason::VerifierMissingAudience,
        ),
        (
            VerifierErrorReason::MissingClientIdentifier,
            pb::OpenId4VpErrorReason::VerifierMissingClientIdentifier,
        ),
        (
            VerifierErrorReason::MissingNonce,
            pb::OpenId4VpErrorReason::VerifierMissingNonce,
        ),
        (
            VerifierErrorReason::IssuerClientIdentifierMismatch,
            pb::OpenId4VpErrorReason::VerifierIssuerClientIdentifierMismatch,
        ),
        (
            VerifierErrorReason::MissingExpiration,
            pb::OpenId4VpErrorReason::VerifierMissingExpiration,
        ),
        (
            VerifierErrorReason::MissingIssuedAt,
            pb::OpenId4VpErrorReason::VerifierMissingIssuedAt,
        ),
        (
            VerifierErrorReason::ClockUnavailable,
            pb::OpenId4VpErrorReason::VerifierClockUnavailable,
        ),
        (
            VerifierErrorReason::RequestObjectExpired,
            pb::OpenId4VpErrorReason::VerifierRequestObjectExpired,
        ),
        (
            VerifierErrorReason::RequestObjectIssuedInFuture,
            pb::OpenId4VpErrorReason::VerifierRequestObjectIssuedInFuture,
        ),
        (
            VerifierErrorReason::RequestObjectLifetimeTooLong,
            pb::OpenId4VpErrorReason::VerifierRequestObjectLifetimeTooLong,
        ),
        (
            VerifierErrorReason::InvalidRequestUri,
            pb::OpenId4VpErrorReason::VerifierInvalidRequestUri,
        ),
        (
            VerifierErrorReason::InvalidBinding,
            pb::OpenId4VpErrorReason::VerifierInvalidBinding,
        ),
        (
            VerifierErrorReason::MissingHolderBindingClaim,
            pb::OpenId4VpErrorReason::VerifierMissingHolderBindingClaim,
        ),
        (
            VerifierErrorReason::HolderBindingAudienceMismatch,
            pb::OpenId4VpErrorReason::VerifierHolderBindingAudienceMismatch,
        ),
        (
            VerifierErrorReason::HolderBindingNonceMismatch,
            pb::OpenId4VpErrorReason::VerifierHolderBindingNonceMismatch,
        ),
        (
            VerifierErrorReason::HolderBindingExpired,
            pb::OpenId4VpErrorReason::VerifierHolderBindingExpired,
        ),
        (
            VerifierErrorReason::BindingExpired,
            pb::OpenId4VpErrorReason::VerifierBindingExpired,
        ),
        (
            VerifierErrorReason::SessionNotFound,
            pb::OpenId4VpErrorReason::VerifierSessionNotFound,
        ),
        (
            VerifierErrorReason::SessionMismatch,
            pb::OpenId4VpErrorReason::VerifierSessionMismatch,
        ),
        (
            VerifierErrorReason::EmptyVpToken,
            pb::OpenId4VpErrorReason::VerifierEmptyVpToken,
        ),
        (
            VerifierErrorReason::EmptyPresentationList,
            pb::OpenId4VpErrorReason::VerifierEmptyPresentationList,
        ),
        (
            VerifierErrorReason::VpTokenQueryMismatch,
            pb::OpenId4VpErrorReason::VerifierVpTokenQueryMismatch,
        ),
        (
            VerifierErrorReason::VpTokenCardinalityMismatch,
            pb::OpenId4VpErrorReason::VerifierVpTokenCardinalityMismatch,
        ),
        (
            VerifierErrorReason::UnsupportedFormat,
            pb::OpenId4VpErrorReason::VerifierUnsupportedFormat,
        ),
        (
            VerifierErrorReason::InvalidZkPresentation,
            pb::OpenId4VpErrorReason::VerifierInvalidZkPresentation,
        ),
        (
            VerifierErrorReason::CredentialRevoked,
            pb::OpenId4VpErrorReason::VerifierCredentialRevoked,
        ),
        (
            VerifierErrorReason::InvalidCredentialStatus,
            pb::OpenId4VpErrorReason::VerifierInvalidCredentialStatus,
        ),
        (
            VerifierErrorReason::CredentialStatusUnavailable,
            pb::OpenId4VpErrorReason::VerifierCredentialStatusUnavailable,
        ),
        (
            VerifierErrorReason::InvalidCredentialValidity,
            pb::OpenId4VpErrorReason::VerifierInvalidCredentialValidity,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(verifier_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_verifier_error_reason(proto)?, domain);
    }
    Ok(())
}

#[test]
fn wallet_error_reasons_round_trip_through_proto() -> Result<(), OpenId4VpProtoError> {
    let cases = [
        (
            WalletErrorReason::InvalidAuthorizationRequestTransport,
            pb::OpenId4VpErrorReason::WalletInvalidAuthorizationRequestTransport,
        ),
        (
            WalletErrorReason::DuplicateAuthorizationRequestParameter,
            pb::OpenId4VpErrorReason::WalletDuplicateAuthorizationRequestParameter,
        ),
        (
            WalletErrorReason::ConflictingRequestObjectParameters,
            pb::OpenId4VpErrorReason::WalletConflictingRequestObjectParameters,
        ),
        (
            WalletErrorReason::MissingWalletNonce,
            pb::OpenId4VpErrorReason::WalletMissingWalletNonce,
        ),
        (
            WalletErrorReason::UnexpectedWalletNonce,
            pb::OpenId4VpErrorReason::WalletUnexpectedWalletNonce,
        ),
        (
            WalletErrorReason::UnsupportedRequestUriMethod,
            pb::OpenId4VpErrorReason::WalletUnsupportedRequestUriMethod,
        ),
        (
            WalletErrorReason::TransportClientIdentifierMismatch,
            pb::OpenId4VpErrorReason::WalletTransportClientIdentifierMismatch,
        ),
        (
            WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
            pb::OpenId4VpErrorReason::WalletResponseEndpointClientIdentifierMismatch,
        ),
        (
            WalletErrorReason::TransportWalletNonceMismatch,
            pb::OpenId4VpErrorReason::WalletTransportWalletNonceMismatch,
        ),
        (
            WalletErrorReason::RequestObjectTooLarge,
            pb::OpenId4VpErrorReason::WalletRequestObjectTooLarge,
        ),
        (
            WalletErrorReason::InvalidRequestObject,
            pb::OpenId4VpErrorReason::WalletInvalidRequestObject,
        ),
        (
            WalletErrorReason::InvalidRequestObjectSignature,
            pb::OpenId4VpErrorReason::WalletInvalidRequestObjectSignature,
        ),
        (
            WalletErrorReason::UnsupportedRequestObjectAlgorithm,
            pb::OpenId4VpErrorReason::WalletUnsupportedRequestObjectAlgorithm,
        ),
        (
            WalletErrorReason::RequestObjectExpired,
            pb::OpenId4VpErrorReason::WalletRequestObjectExpired,
        ),
        (
            WalletErrorReason::RequestObjectIssuedInFuture,
            pb::OpenId4VpErrorReason::WalletRequestObjectIssuedInFuture,
        ),
        (
            WalletErrorReason::InvalidClientIdentifierPrefix,
            pb::OpenId4VpErrorReason::WalletInvalidClientIdentifierPrefix,
        ),
        (
            WalletErrorReason::InvalidVerifierAttestation,
            pb::OpenId4VpErrorReason::WalletInvalidVerifierAttestation,
        ),
        (
            WalletErrorReason::InvalidMetadataReference,
            pb::OpenId4VpErrorReason::WalletInvalidMetadataReference,
        ),
        (
            WalletErrorReason::ExpectedOriginMismatch,
            pb::OpenId4VpErrorReason::WalletExpectedOriginMismatch,
        ),
        (
            WalletErrorReason::UnsupportedFeature,
            pb::OpenId4VpErrorReason::WalletUnsupportedFeature,
        ),
        (
            WalletErrorReason::ZkDerivationFailed,
            pb::OpenId4VpErrorReason::WalletZkDerivationFailed,
        ),
        (
            WalletErrorReason::MissingX509CertificateChain,
            pb::OpenId4VpErrorReason::WalletMissingX509CertificateChain,
        ),
        (
            WalletErrorReason::MalformedX509CertificateChain,
            pb::OpenId4VpErrorReason::WalletMalformedX509CertificateChain,
        ),
        (
            WalletErrorReason::UnsupportedX509CertificateAlgorithm,
            pb::OpenId4VpErrorReason::WalletUnsupportedX509CertificateAlgorithm,
        ),
        (
            WalletErrorReason::X509LeafKeyMismatch,
            pb::OpenId4VpErrorReason::WalletX509LeafKeyMismatch,
        ),
        (
            WalletErrorReason::X509CertificateHashMismatch,
            pb::OpenId4VpErrorReason::WalletX509CertificateHashMismatch,
        ),
        (
            WalletErrorReason::X509CertificateSanMismatch,
            pb::OpenId4VpErrorReason::WalletX509CertificateSanMismatch,
        ),
        (
            WalletErrorReason::X509CertificatePathRejected,
            pb::OpenId4VpErrorReason::WalletX509CertificatePathRejected,
        ),
        (
            WalletErrorReason::X509TrustEvidenceUnavailable,
            pb::OpenId4VpErrorReason::WalletX509TrustEvidenceUnavailable,
        ),
        (
            WalletErrorReason::X509TrustEvidenceStale,
            pb::OpenId4VpErrorReason::WalletX509TrustEvidenceStale,
        ),
        (
            WalletErrorReason::UnsupportedClientIdentifierMode,
            pb::OpenId4VpErrorReason::WalletUnsupportedClientIdentifierMode,
        ),
        (
            WalletErrorReason::InvalidTransactionData,
            pb::OpenId4VpErrorReason::WalletInvalidTransactionData,
        ),
    ];
    for (domain, proto) in cases {
        assert_eq!(wallet_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_wallet_error_reason(proto)?, domain);
    }
    Ok(())
}

#[test]
fn format_dc_api_and_codec_reasons_round_trip_through_proto() -> Result<(), OpenId4VpProtoError> {
    let mdoc_cases = [
        (
            MdocFormatErrorReason::InvalidDeviceResponse,
            pb::OpenId4VpErrorReason::MdocInvalidDeviceResponse,
        ),
        (
            MdocFormatErrorReason::InvalidIssuerAuthentication,
            pb::OpenId4VpErrorReason::MdocInvalidIssuerAuthentication,
        ),
        (
            MdocFormatErrorReason::InvalidDeviceAuthentication,
            pb::OpenId4VpErrorReason::MdocInvalidDeviceAuthentication,
        ),
        (
            MdocFormatErrorReason::SessionTranscriptMismatch,
            pb::OpenId4VpErrorReason::MdocSessionTranscriptMismatch,
        ),
        (
            MdocFormatErrorReason::DocumentTypeMismatch,
            pb::OpenId4VpErrorReason::MdocDocumentTypeMismatch,
        ),
        (
            MdocFormatErrorReason::Expired,
            pb::OpenId4VpErrorReason::MdocExpired,
        ),
        (
            MdocFormatErrorReason::UnsupportedOperation,
            pb::OpenId4VpErrorReason::MdocUnsupportedOperation,
        ),
    ];
    for (domain, proto) in mdoc_cases {
        assert_eq!(mdoc_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_mdoc_error_reason(proto)?, domain);
    }

    let zk_cases = [
        (
            ZkFormatErrorReason::UnknownCircuit,
            pb::OpenId4VpErrorReason::ZkUnknownCircuit,
        ),
        (
            ZkFormatErrorReason::UnsupportedCircuit,
            pb::OpenId4VpErrorReason::ZkUnsupportedCircuit,
        ),
        (
            ZkFormatErrorReason::UnsupportedProofSuite,
            pb::OpenId4VpErrorReason::ZkUnsupportedProofSuite,
        ),
        (
            ZkFormatErrorReason::InvalidPresentationEncoding,
            pb::OpenId4VpErrorReason::ZkInvalidPresentationEncoding,
        ),
        (
            ZkFormatErrorReason::InvalidProof,
            pb::OpenId4VpErrorReason::ZkInvalidProof,
        ),
        (
            ZkFormatErrorReason::BindingMismatch,
            pb::OpenId4VpErrorReason::ZkBindingMismatch,
        ),
        (
            ZkFormatErrorReason::VerifierUnavailable,
            pb::OpenId4VpErrorReason::ZkVerifierUnavailable,
        ),
        (
            ZkFormatErrorReason::CircuitVerificationMismatch,
            pb::OpenId4VpErrorReason::ZkCircuitVerificationMismatch,
        ),
    ];
    for (domain, proto) in zk_cases {
        assert_eq!(zk_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_zk_error_reason(proto)?, domain);
    }

    let dc_api_cases = [
        (
            DcApiErrorReason::EmptyValue,
            pb::OpenId4VpErrorReason::DcApiEmptyValue,
        ),
        (
            DcApiErrorReason::EmptyRequestSet,
            pb::OpenId4VpErrorReason::DcApiEmptyRequestSet,
        ),
        (
            DcApiErrorReason::InvalidProtocol,
            pb::OpenId4VpErrorReason::DcApiInvalidProtocol,
        ),
        (
            DcApiErrorReason::HandoverEncodingFailed,
            pb::OpenId4VpErrorReason::DcApiHandoverEncodingFailed,
        ),
        (
            DcApiErrorReason::InvalidRequestObject,
            pb::OpenId4VpErrorReason::DcApiInvalidRequestObject,
        ),
        (
            DcApiErrorReason::RequestObjectTooLarge,
            pb::OpenId4VpErrorReason::DcApiRequestObjectTooLarge,
        ),
        (
            DcApiErrorReason::TooManyRequestObjectSignatures,
            pb::OpenId4VpErrorReason::DcApiTooManyRequestObjectSignatures,
        ),
    ];
    for (domain, proto) in dc_api_cases {
        assert_eq!(dc_api_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_dc_api_error_reason(proto)?, domain);
    }

    let codec_cases = [
        (
            OpenId4VpProtoError::Decode,
            pb::OpenId4VpErrorReason::ProtoDecode,
        ),
        (
            OpenId4VpProtoError::Encode,
            pb::OpenId4VpErrorReason::ProtoEncode,
        ),
        (
            OpenId4VpProtoError::MissingField,
            pb::OpenId4VpErrorReason::ProtoMissingField,
        ),
        (
            OpenId4VpProtoError::InvalidEnumValue,
            pb::OpenId4VpErrorReason::ProtoInvalidEnumValue,
        ),
        (
            OpenId4VpProtoError::InvalidField,
            pb::OpenId4VpErrorReason::ProtoInvalidField,
        ),
        (
            OpenId4VpProtoError::JsonSerialize,
            pb::OpenId4VpErrorReason::ProtoJsonSerialize,
        ),
        (
            OpenId4VpProtoError::JsonDeserialize,
            pb::OpenId4VpErrorReason::ProtoJsonDeserialize,
        ),
        (
            OpenId4VpProtoError::JsonTooLarge,
            pb::OpenId4VpErrorReason::ProtoJsonTooLarge,
        ),
        (
            OpenId4VpProtoError::JsonNestingTooDeep,
            pb::OpenId4VpErrorReason::ProtoJsonNestingTooDeep,
        ),
        (
            OpenId4VpProtoError::JsonDuplicateKey,
            pb::OpenId4VpErrorReason::ProtoJsonDuplicateKey,
        ),
    ];
    for (domain, proto) in codec_cases {
        assert_eq!(proto_error_reason_to_proto(domain), proto);
        assert_eq!(proto_to_proto_error_reason(proto)?, domain);
    }

    Ok(())
}

#[test]
fn common_identity_stack_error_wraps_openid4vp_reason() -> Result<(), OpenId4VpProtoError> {
    let error = identity_stack_error_from_reason(
        pb::OpenId4VpErrorReason::VerifierUnsupportedFormat,
        Some("corr-01"),
    );
    assert_eq!(
        error.domain.as_known(),
        Some(IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VP)
    );
    assert_eq!(
        error.reason_code,
        error_reason_code(pb::OpenId4VpErrorReason::VerifierUnsupportedFormat)
    );
    assert_eq!(error.correlation_id, "corr-01");
    assert_eq!(
        error_reason_from_identity_stack_error(&error)?,
        pb::OpenId4VpErrorReason::VerifierUnsupportedFormat
    );

    let wrong_domain = IdentityStackError {
        domain: IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VCI.into(),
        reason_code: error_reason_code(pb::OpenId4VpErrorReason::VerifierUnsupportedFormat),
        ..IdentityStackError::default()
    };
    assert_eq!(
        error_reason_from_identity_stack_error(&wrong_domain),
        Err(OpenId4VpProtoError::InvalidEnumValue)
    );
    assert_eq!(
        error_reason_from_i32(i32::MAX),
        Err(OpenId4VpProtoError::InvalidEnumValue)
    );
    Ok(())
}

#[test]
fn generated_error_reason_json_uses_proto_enum_name() -> Result<(), serde_json::Error> {
    let serialized = serde_json::to_value(pb::OpenId4VpErrorReason::VerifierUnsupportedFormat)?;
    assert_eq!(
        serialized,
        serde_json::Value::String(
            "OPEN_ID4_VP_ERROR_REASON_VERIFIER_UNSUPPORTED_FORMAT".to_owned()
        )
    );
    Ok(())
}
