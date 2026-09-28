// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Maps public OpenID4VP errors to generated protobuf reason codes.

use buffa::{EnumValue, Enumeration};
use reallyme_openid4vp_dc_api::DcApiErrorReason;
use reallyme_openid4vp_dcql::DcqlErrorReason;
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_openid4vp_formats::mdoc::MdocFormatErrorReason;
use reallyme_openid4vp_formats::ZkFormatErrorReason;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{OpenId4vpTypeErrorReason, ProblemKind};
use reallyme_openid4vp_verifier::VerifierErrorReason;
use reallyme_openid4vp_wallet::WalletErrorReason;
use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
    IdentityStackError, IdentityStackErrorDomain,
};

use crate::OpenId4VpProtoError;

const OPENID4VP_DOMAIN: IdentityStackErrorDomain =
    IdentityStackErrorDomain::IDENTITY_STACK_ERROR_DOMAIN_OPENID4VP;

macro_rules! to_proto {
    ($value:expr, $fallback:path, { $($source:path => $target:path),+ $(,)? }) => {
        match $value {
            $($source => $target,)+
            _ => $fallback,
        }
    };
}

macro_rules! from_proto {
    ($value:expr, { $($source:path => $target:path),+ $(,)? }) => {
        match $value {
            $($source => Ok($target),)+
            _ => Err(OpenId4VpProtoError::InvalidEnumValue),
        }
    };
}

/// Convert a public OpenID4VP type error reason into its local protobuf reason.
pub fn type_error_reason_to_proto(value: OpenId4vpTypeErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemInvalidRequest, {
        OpenId4vpTypeErrorReason::EmptyValue => pb::OpenId4VpErrorReason::TypeEmptyValue,
        OpenId4vpTypeErrorReason::EmptyCollection => pb::OpenId4VpErrorReason::TypeEmptyCollection,
        OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix => pb::OpenId4VpErrorReason::TypeInvalidClientIdentifierPrefix,
        OpenId4vpTypeErrorReason::UnsupportedMetadataCapability => pb::OpenId4VpErrorReason::TypeUnsupportedMetadataCapability,
        OpenId4vpTypeErrorReason::UnsupportedTransactionDataHashAlgorithm => pb::OpenId4VpErrorReason::TypeUnsupportedTransactionDataHashAlgorithm,
        OpenId4vpTypeErrorReason::InvalidRequestObjectJwt => pb::OpenId4VpErrorReason::TypeInvalidRequestObjectJwt,
        OpenId4vpTypeErrorReason::SerializationFailed => pb::OpenId4VpErrorReason::TypeSerializationFailed,
        OpenId4vpTypeErrorReason::InvalidEncoding => pb::OpenId4VpErrorReason::TypeInvalidEncoding,
        OpenId4vpTypeErrorReason::JsonDepthExceeded => pb::OpenId4VpErrorReason::TypeJsonDepthExceeded,
        OpenId4vpTypeErrorReason::JsonSizeExceeded => pb::OpenId4VpErrorReason::TypeJsonSizeExceeded,
        OpenId4vpTypeErrorReason::DuplicateJsonKey => pb::OpenId4VpErrorReason::TypeDuplicateJsonKey,
        OpenId4vpTypeErrorReason::EmptyPresentationList => pb::OpenId4VpErrorReason::TypeEmptyPresentationList,
    })
}

/// Convert a local protobuf reason back to an OpenID4VP type error reason.
pub fn proto_to_type_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<OpenId4vpTypeErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::TypeEmptyValue => OpenId4vpTypeErrorReason::EmptyValue,
        pb::OpenId4VpErrorReason::TypeEmptyCollection => OpenId4vpTypeErrorReason::EmptyCollection,
        pb::OpenId4VpErrorReason::TypeInvalidClientIdentifierPrefix => OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix,
        pb::OpenId4VpErrorReason::TypeUnsupportedMetadataCapability => OpenId4vpTypeErrorReason::UnsupportedMetadataCapability,
        pb::OpenId4VpErrorReason::TypeUnsupportedTransactionDataHashAlgorithm => OpenId4vpTypeErrorReason::UnsupportedTransactionDataHashAlgorithm,
        pb::OpenId4VpErrorReason::TypeInvalidRequestObjectJwt => OpenId4vpTypeErrorReason::InvalidRequestObjectJwt,
        pb::OpenId4VpErrorReason::TypeSerializationFailed => OpenId4vpTypeErrorReason::SerializationFailed,
        pb::OpenId4VpErrorReason::TypeInvalidEncoding => OpenId4vpTypeErrorReason::InvalidEncoding,
        pb::OpenId4VpErrorReason::TypeJsonDepthExceeded => OpenId4vpTypeErrorReason::JsonDepthExceeded,
        pb::OpenId4VpErrorReason::TypeJsonSizeExceeded => OpenId4vpTypeErrorReason::JsonSizeExceeded,
        pb::OpenId4VpErrorReason::TypeDuplicateJsonKey => OpenId4vpTypeErrorReason::DuplicateJsonKey,
        pb::OpenId4VpErrorReason::TypeEmptyPresentationList => OpenId4vpTypeErrorReason::EmptyPresentationList,
    })
}

/// Convert an RFC 9457 problem kind into its local protobuf reason.
pub fn problem_kind_to_error_reason(value: ProblemKind) -> pb::OpenId4VpErrorReason {
    match value {
        ProblemKind::InvalidRequest => pb::OpenId4VpErrorReason::ProblemInvalidRequest,
        ProblemKind::InvalidRequestObject => pb::OpenId4VpErrorReason::ProblemInvalidRequestObject,
        ProblemKind::InvalidClientIdentifier => {
            pb::OpenId4VpErrorReason::ProblemInvalidClientIdentifier
        }
        ProblemKind::InvalidDcqlQuery => pb::OpenId4VpErrorReason::ProblemInvalidDcqlQuery,
        ProblemKind::UnsatisfiedDcqlQuery => pb::OpenId4VpErrorReason::ProblemUnsatisfiedDcqlQuery,
        ProblemKind::BindingExpired => pb::OpenId4VpErrorReason::ProblemBindingExpired,
        ProblemKind::SessionNotFound => pb::OpenId4VpErrorReason::ProblemSessionNotFound,
        ProblemKind::SessionMismatch => pb::OpenId4VpErrorReason::ProblemSessionMismatch,
        ProblemKind::UnsupportedFeature => pb::OpenId4VpErrorReason::ProblemUnsupportedFeature,
        ProblemKind::WalletUnavailable => pb::OpenId4VpErrorReason::ProblemWalletUnavailable,
        ProblemKind::Internal => pb::OpenId4VpErrorReason::ProblemInternal,
    }
}

/// Convert a local protobuf reason back to an RFC 9457 problem kind.
pub fn error_reason_to_problem_kind(
    value: pb::OpenId4VpErrorReason,
) -> Result<ProblemKind, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::ProblemInvalidRequest => ProblemKind::InvalidRequest,
        pb::OpenId4VpErrorReason::ProblemInvalidRequestObject => ProblemKind::InvalidRequestObject,
        pb::OpenId4VpErrorReason::ProblemInvalidClientIdentifier => ProblemKind::InvalidClientIdentifier,
        pb::OpenId4VpErrorReason::ProblemInvalidDcqlQuery => ProblemKind::InvalidDcqlQuery,
        pb::OpenId4VpErrorReason::ProblemUnsatisfiedDcqlQuery => ProblemKind::UnsatisfiedDcqlQuery,
        pb::OpenId4VpErrorReason::ProblemBindingExpired => ProblemKind::BindingExpired,
        pb::OpenId4VpErrorReason::ProblemSessionNotFound => ProblemKind::SessionNotFound,
        pb::OpenId4VpErrorReason::ProblemSessionMismatch => ProblemKind::SessionMismatch,
        pb::OpenId4VpErrorReason::ProblemUnsupportedFeature => ProblemKind::UnsupportedFeature,
        pb::OpenId4VpErrorReason::ProblemWalletUnavailable => ProblemKind::WalletUnavailable,
        pb::OpenId4VpErrorReason::ProblemInternal => ProblemKind::Internal,
    })
}

/// Convert a public DCQL error reason into its local protobuf reason.
pub fn dcql_error_reason_to_proto(value: DcqlErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemInvalidDcqlQuery, {
        DcqlErrorReason::InvalidJson => pb::OpenId4VpErrorReason::DcqlInvalidJson,
        DcqlErrorReason::DuplicateJsonKey => pb::OpenId4VpErrorReason::DcqlDuplicateJsonKey,
        DcqlErrorReason::EmptyValue => pb::OpenId4VpErrorReason::DcqlEmptyValue,
        DcqlErrorReason::InvalidIdentifier => pb::OpenId4VpErrorReason::DcqlInvalidIdentifier,
        DcqlErrorReason::DuplicateIdentifier => pb::OpenId4VpErrorReason::DcqlDuplicateIdentifier,
        DcqlErrorReason::ClaimSetsWithoutClaims => pb::OpenId4VpErrorReason::DcqlClaimSetsWithoutClaims,
        DcqlErrorReason::MissingClaimIdentifier => pb::OpenId4VpErrorReason::DcqlMissingClaimIdentifier,
        DcqlErrorReason::UnsupportedTrustedAuthorityType => pb::OpenId4VpErrorReason::DcqlUnsupportedTrustedAuthorityType,
        DcqlErrorReason::UnsupportedClaimProperty => pb::OpenId4VpErrorReason::DcqlUnsupportedClaimProperty,
        DcqlErrorReason::UnknownReference => pb::OpenId4VpErrorReason::DcqlUnknownReference,
        DcqlErrorReason::InvalidClaimsPath => pb::OpenId4VpErrorReason::DcqlInvalidClaimsPath,
        DcqlErrorReason::ClaimsPathMismatch => pb::OpenId4VpErrorReason::DcqlClaimsPathMismatch,
        DcqlErrorReason::InvalidClaimValue => pb::OpenId4VpErrorReason::DcqlInvalidClaimValue,
        DcqlErrorReason::QueryTooLarge => pb::OpenId4VpErrorReason::DcqlQueryTooLarge,
        DcqlErrorReason::InvalidCredentialMetadata => pb::OpenId4VpErrorReason::DcqlInvalidCredentialMetadata,
        DcqlErrorReason::UnsatisfiedRequiredCredential => pb::OpenId4VpErrorReason::DcqlUnsatisfiedRequiredCredential,
    })
}

/// Convert a local protobuf reason back to a public DCQL error reason.
pub fn proto_to_dcql_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<DcqlErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::DcqlInvalidJson => DcqlErrorReason::InvalidJson,
        pb::OpenId4VpErrorReason::DcqlDuplicateJsonKey => DcqlErrorReason::DuplicateJsonKey,
        pb::OpenId4VpErrorReason::DcqlEmptyValue => DcqlErrorReason::EmptyValue,
        pb::OpenId4VpErrorReason::DcqlInvalidIdentifier => DcqlErrorReason::InvalidIdentifier,
        pb::OpenId4VpErrorReason::DcqlDuplicateIdentifier => DcqlErrorReason::DuplicateIdentifier,
        pb::OpenId4VpErrorReason::DcqlClaimSetsWithoutClaims => DcqlErrorReason::ClaimSetsWithoutClaims,
        pb::OpenId4VpErrorReason::DcqlMissingClaimIdentifier => DcqlErrorReason::MissingClaimIdentifier,
        pb::OpenId4VpErrorReason::DcqlUnsupportedTrustedAuthorityType => DcqlErrorReason::UnsupportedTrustedAuthorityType,
        pb::OpenId4VpErrorReason::DcqlUnsupportedClaimProperty => DcqlErrorReason::UnsupportedClaimProperty,
        pb::OpenId4VpErrorReason::DcqlUnknownReference => DcqlErrorReason::UnknownReference,
        pb::OpenId4VpErrorReason::DcqlInvalidClaimsPath => DcqlErrorReason::InvalidClaimsPath,
        pb::OpenId4VpErrorReason::DcqlClaimsPathMismatch => DcqlErrorReason::ClaimsPathMismatch,
        pb::OpenId4VpErrorReason::DcqlInvalidClaimValue => DcqlErrorReason::InvalidClaimValue,
        pb::OpenId4VpErrorReason::DcqlQueryTooLarge => DcqlErrorReason::QueryTooLarge,
        pb::OpenId4VpErrorReason::DcqlInvalidCredentialMetadata => DcqlErrorReason::InvalidCredentialMetadata,
        pb::OpenId4VpErrorReason::DcqlUnsatisfiedRequiredCredential => DcqlErrorReason::UnsatisfiedRequiredCredential,
    })
}

/// Convert a public verifier error reason into its local protobuf reason.
pub fn verifier_error_reason_to_proto(value: VerifierErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemInvalidRequest, {
        VerifierErrorReason::InvalidRequestObject => pb::OpenId4VpErrorReason::VerifierInvalidRequestObject,
        VerifierErrorReason::MissingIssuer => pb::OpenId4VpErrorReason::VerifierMissingIssuer,
        VerifierErrorReason::MissingAudience => pb::OpenId4VpErrorReason::VerifierMissingAudience,
        VerifierErrorReason::MissingClientIdentifier => pb::OpenId4VpErrorReason::VerifierMissingClientIdentifier,
        VerifierErrorReason::MissingNonce => pb::OpenId4VpErrorReason::VerifierMissingNonce,
        VerifierErrorReason::IssuerClientIdentifierMismatch => pb::OpenId4VpErrorReason::VerifierIssuerClientIdentifierMismatch,
        VerifierErrorReason::MissingExpiration => pb::OpenId4VpErrorReason::VerifierMissingExpiration,
        VerifierErrorReason::MissingIssuedAt => pb::OpenId4VpErrorReason::VerifierMissingIssuedAt,
        VerifierErrorReason::ClockUnavailable => pb::OpenId4VpErrorReason::VerifierClockUnavailable,
        VerifierErrorReason::RequestObjectExpired => pb::OpenId4VpErrorReason::VerifierRequestObjectExpired,
        VerifierErrorReason::RequestObjectIssuedInFuture => pb::OpenId4VpErrorReason::VerifierRequestObjectIssuedInFuture,
        VerifierErrorReason::RequestObjectLifetimeTooLong => pb::OpenId4VpErrorReason::VerifierRequestObjectLifetimeTooLong,
        VerifierErrorReason::InvalidRequestUri => pb::OpenId4VpErrorReason::VerifierInvalidRequestUri,
        VerifierErrorReason::InvalidBinding => pb::OpenId4VpErrorReason::VerifierInvalidBinding,
        VerifierErrorReason::MissingHolderBindingClaim => pb::OpenId4VpErrorReason::VerifierMissingHolderBindingClaim,
        VerifierErrorReason::HolderBindingAudienceMismatch => pb::OpenId4VpErrorReason::VerifierHolderBindingAudienceMismatch,
        VerifierErrorReason::HolderBindingNonceMismatch => pb::OpenId4VpErrorReason::VerifierHolderBindingNonceMismatch,
        VerifierErrorReason::HolderBindingExpired => pb::OpenId4VpErrorReason::VerifierHolderBindingExpired,
        VerifierErrorReason::BindingExpired => pb::OpenId4VpErrorReason::VerifierBindingExpired,
        VerifierErrorReason::SessionNotFound => pb::OpenId4VpErrorReason::VerifierSessionNotFound,
        VerifierErrorReason::SessionMismatch => pb::OpenId4VpErrorReason::VerifierSessionMismatch,
        VerifierErrorReason::EmptyVpToken => pb::OpenId4VpErrorReason::VerifierEmptyVpToken,
        VerifierErrorReason::EmptyPresentationList => pb::OpenId4VpErrorReason::VerifierEmptyPresentationList,
        VerifierErrorReason::VpTokenQueryMismatch => pb::OpenId4VpErrorReason::VerifierVpTokenQueryMismatch,
        VerifierErrorReason::VpTokenCardinalityMismatch => pb::OpenId4VpErrorReason::VerifierVpTokenCardinalityMismatch,
        VerifierErrorReason::UnsupportedFormat => pb::OpenId4VpErrorReason::VerifierUnsupportedFormat,
        VerifierErrorReason::InvalidZkPresentation => pb::OpenId4VpErrorReason::VerifierInvalidZkPresentation,
        VerifierErrorReason::CredentialRevoked => pb::OpenId4VpErrorReason::VerifierCredentialRevoked,
        VerifierErrorReason::InvalidCredentialStatus => pb::OpenId4VpErrorReason::VerifierInvalidCredentialStatus,
        VerifierErrorReason::CredentialStatusUnavailable => pb::OpenId4VpErrorReason::VerifierCredentialStatusUnavailable,
        VerifierErrorReason::InvalidCredentialValidity => pb::OpenId4VpErrorReason::VerifierInvalidCredentialValidity,
    })
}

/// Convert a local protobuf reason back to a public verifier error reason.
pub fn proto_to_verifier_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<VerifierErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::VerifierInvalidRequestObject => VerifierErrorReason::InvalidRequestObject,
        pb::OpenId4VpErrorReason::VerifierMissingIssuer => VerifierErrorReason::MissingIssuer,
        pb::OpenId4VpErrorReason::VerifierMissingAudience => VerifierErrorReason::MissingAudience,
        pb::OpenId4VpErrorReason::VerifierMissingClientIdentifier => VerifierErrorReason::MissingClientIdentifier,
        pb::OpenId4VpErrorReason::VerifierMissingNonce => VerifierErrorReason::MissingNonce,
        pb::OpenId4VpErrorReason::VerifierIssuerClientIdentifierMismatch => VerifierErrorReason::IssuerClientIdentifierMismatch,
        pb::OpenId4VpErrorReason::VerifierMissingExpiration => VerifierErrorReason::MissingExpiration,
        pb::OpenId4VpErrorReason::VerifierMissingIssuedAt => VerifierErrorReason::MissingIssuedAt,
        pb::OpenId4VpErrorReason::VerifierClockUnavailable => VerifierErrorReason::ClockUnavailable,
        pb::OpenId4VpErrorReason::VerifierRequestObjectExpired => VerifierErrorReason::RequestObjectExpired,
        pb::OpenId4VpErrorReason::VerifierRequestObjectIssuedInFuture => VerifierErrorReason::RequestObjectIssuedInFuture,
        pb::OpenId4VpErrorReason::VerifierRequestObjectLifetimeTooLong => VerifierErrorReason::RequestObjectLifetimeTooLong,
        pb::OpenId4VpErrorReason::VerifierInvalidRequestUri => VerifierErrorReason::InvalidRequestUri,
        pb::OpenId4VpErrorReason::VerifierInvalidBinding => VerifierErrorReason::InvalidBinding,
        pb::OpenId4VpErrorReason::VerifierMissingHolderBindingClaim => VerifierErrorReason::MissingHolderBindingClaim,
        pb::OpenId4VpErrorReason::VerifierHolderBindingAudienceMismatch => VerifierErrorReason::HolderBindingAudienceMismatch,
        pb::OpenId4VpErrorReason::VerifierHolderBindingNonceMismatch => VerifierErrorReason::HolderBindingNonceMismatch,
        pb::OpenId4VpErrorReason::VerifierHolderBindingExpired => VerifierErrorReason::HolderBindingExpired,
        pb::OpenId4VpErrorReason::VerifierBindingExpired => VerifierErrorReason::BindingExpired,
        pb::OpenId4VpErrorReason::VerifierSessionNotFound => VerifierErrorReason::SessionNotFound,
        pb::OpenId4VpErrorReason::VerifierSessionMismatch => VerifierErrorReason::SessionMismatch,
        pb::OpenId4VpErrorReason::VerifierEmptyVpToken => VerifierErrorReason::EmptyVpToken,
        pb::OpenId4VpErrorReason::VerifierEmptyPresentationList => VerifierErrorReason::EmptyPresentationList,
        pb::OpenId4VpErrorReason::VerifierVpTokenQueryMismatch => VerifierErrorReason::VpTokenQueryMismatch,
        pb::OpenId4VpErrorReason::VerifierVpTokenCardinalityMismatch => VerifierErrorReason::VpTokenCardinalityMismatch,
        pb::OpenId4VpErrorReason::VerifierUnsupportedFormat => VerifierErrorReason::UnsupportedFormat,
        pb::OpenId4VpErrorReason::VerifierInvalidZkPresentation => VerifierErrorReason::InvalidZkPresentation,
        pb::OpenId4VpErrorReason::VerifierCredentialRevoked => VerifierErrorReason::CredentialRevoked,
        pb::OpenId4VpErrorReason::VerifierInvalidCredentialStatus => VerifierErrorReason::InvalidCredentialStatus,
        pb::OpenId4VpErrorReason::VerifierCredentialStatusUnavailable => VerifierErrorReason::CredentialStatusUnavailable,
        pb::OpenId4VpErrorReason::VerifierInvalidCredentialValidity => VerifierErrorReason::InvalidCredentialValidity,
    })
}

/// Convert a public wallet error reason into its local protobuf reason.
pub fn wallet_error_reason_to_proto(value: WalletErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemWalletUnavailable, {
        WalletErrorReason::InvalidAuthorizationRequestTransport => pb::OpenId4VpErrorReason::WalletInvalidAuthorizationRequestTransport,
        WalletErrorReason::DuplicateAuthorizationRequestParameter => pb::OpenId4VpErrorReason::WalletDuplicateAuthorizationRequestParameter,
        WalletErrorReason::ConflictingRequestObjectParameters => pb::OpenId4VpErrorReason::WalletConflictingRequestObjectParameters,
        WalletErrorReason::MissingWalletNonce => pb::OpenId4VpErrorReason::WalletMissingWalletNonce,
        WalletErrorReason::UnexpectedWalletNonce => pb::OpenId4VpErrorReason::WalletUnexpectedWalletNonce,
        WalletErrorReason::UnsupportedRequestUriMethod => pb::OpenId4VpErrorReason::WalletUnsupportedRequestUriMethod,
        WalletErrorReason::TransportClientIdentifierMismatch => pb::OpenId4VpErrorReason::WalletTransportClientIdentifierMismatch,
        WalletErrorReason::ResponseEndpointClientIdentifierMismatch => pb::OpenId4VpErrorReason::WalletResponseEndpointClientIdentifierMismatch,
        WalletErrorReason::TransportWalletNonceMismatch => pb::OpenId4VpErrorReason::WalletTransportWalletNonceMismatch,
        WalletErrorReason::RequestObjectTooLarge => pb::OpenId4VpErrorReason::WalletRequestObjectTooLarge,
        WalletErrorReason::InvalidRequestObject => pb::OpenId4VpErrorReason::WalletInvalidRequestObject,
        WalletErrorReason::RequestObjectExpired => pb::OpenId4VpErrorReason::WalletRequestObjectExpired,
        WalletErrorReason::RequestObjectIssuedInFuture => pb::OpenId4VpErrorReason::WalletRequestObjectIssuedInFuture,
        WalletErrorReason::InvalidClientIdentifierPrefix => pb::OpenId4VpErrorReason::WalletInvalidClientIdentifierPrefix,
        WalletErrorReason::InvalidVerifierAttestation => pb::OpenId4VpErrorReason::WalletInvalidVerifierAttestation,
        WalletErrorReason::InvalidMetadataReference => pb::OpenId4VpErrorReason::WalletInvalidMetadataReference,
        WalletErrorReason::ExpectedOriginMismatch => pb::OpenId4VpErrorReason::WalletExpectedOriginMismatch,
        WalletErrorReason::UnsupportedFeature => pb::OpenId4VpErrorReason::WalletUnsupportedFeature,
        WalletErrorReason::ZkDerivationFailed => pb::OpenId4VpErrorReason::WalletZkDerivationFailed,
        WalletErrorReason::MissingX509CertificateChain => pb::OpenId4VpErrorReason::WalletMissingX509CertificateChain,
        WalletErrorReason::MalformedX509CertificateChain => pb::OpenId4VpErrorReason::WalletMalformedX509CertificateChain,
        WalletErrorReason::UnsupportedX509CertificateAlgorithm => pb::OpenId4VpErrorReason::WalletUnsupportedX509CertificateAlgorithm,
        WalletErrorReason::X509LeafKeyMismatch => pb::OpenId4VpErrorReason::WalletX509LeafKeyMismatch,
        WalletErrorReason::X509CertificateHashMismatch => pb::OpenId4VpErrorReason::WalletX509CertificateHashMismatch,
        WalletErrorReason::X509CertificateSanMismatch => pb::OpenId4VpErrorReason::WalletX509CertificateSanMismatch,
        WalletErrorReason::X509CertificatePathRejected => pb::OpenId4VpErrorReason::WalletX509CertificatePathRejected,
        WalletErrorReason::X509TrustEvidenceUnavailable => pb::OpenId4VpErrorReason::WalletX509TrustEvidenceUnavailable,
        WalletErrorReason::X509TrustEvidenceStale => pb::OpenId4VpErrorReason::WalletX509TrustEvidenceStale,
        WalletErrorReason::UnsupportedClientIdentifierMode => pb::OpenId4VpErrorReason::WalletUnsupportedClientIdentifierMode,
        WalletErrorReason::InvalidRequestObjectSignature => pb::OpenId4VpErrorReason::WalletInvalidRequestObjectSignature,
        WalletErrorReason::UnsupportedRequestObjectAlgorithm => pb::OpenId4VpErrorReason::WalletUnsupportedRequestObjectAlgorithm,
        WalletErrorReason::InvalidTransactionData => pb::OpenId4VpErrorReason::WalletInvalidTransactionData,
    })
}

/// Convert a local protobuf reason back to a public wallet error reason.
pub fn proto_to_wallet_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<WalletErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::WalletInvalidAuthorizationRequestTransport => WalletErrorReason::InvalidAuthorizationRequestTransport,
        pb::OpenId4VpErrorReason::WalletDuplicateAuthorizationRequestParameter => WalletErrorReason::DuplicateAuthorizationRequestParameter,
        pb::OpenId4VpErrorReason::WalletConflictingRequestObjectParameters => WalletErrorReason::ConflictingRequestObjectParameters,
        pb::OpenId4VpErrorReason::WalletMissingWalletNonce => WalletErrorReason::MissingWalletNonce,
        pb::OpenId4VpErrorReason::WalletUnexpectedWalletNonce => WalletErrorReason::UnexpectedWalletNonce,
        pb::OpenId4VpErrorReason::WalletUnsupportedRequestUriMethod => WalletErrorReason::UnsupportedRequestUriMethod,
        pb::OpenId4VpErrorReason::WalletTransportClientIdentifierMismatch => WalletErrorReason::TransportClientIdentifierMismatch,
        pb::OpenId4VpErrorReason::WalletResponseEndpointClientIdentifierMismatch => WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
        pb::OpenId4VpErrorReason::WalletTransportWalletNonceMismatch => WalletErrorReason::TransportWalletNonceMismatch,
        pb::OpenId4VpErrorReason::WalletRequestObjectTooLarge => WalletErrorReason::RequestObjectTooLarge,
        pb::OpenId4VpErrorReason::WalletInvalidRequestObject => WalletErrorReason::InvalidRequestObject,
        pb::OpenId4VpErrorReason::WalletRequestObjectExpired => WalletErrorReason::RequestObjectExpired,
        pb::OpenId4VpErrorReason::WalletRequestObjectIssuedInFuture => WalletErrorReason::RequestObjectIssuedInFuture,
        pb::OpenId4VpErrorReason::WalletInvalidClientIdentifierPrefix => WalletErrorReason::InvalidClientIdentifierPrefix,
        pb::OpenId4VpErrorReason::WalletInvalidVerifierAttestation => WalletErrorReason::InvalidVerifierAttestation,
        pb::OpenId4VpErrorReason::WalletInvalidMetadataReference => WalletErrorReason::InvalidMetadataReference,
        pb::OpenId4VpErrorReason::WalletExpectedOriginMismatch => WalletErrorReason::ExpectedOriginMismatch,
        pb::OpenId4VpErrorReason::WalletUnsupportedFeature => WalletErrorReason::UnsupportedFeature,
        pb::OpenId4VpErrorReason::WalletZkDerivationFailed => WalletErrorReason::ZkDerivationFailed,
        pb::OpenId4VpErrorReason::WalletMissingX509CertificateChain => WalletErrorReason::MissingX509CertificateChain,
        pb::OpenId4VpErrorReason::WalletMalformedX509CertificateChain => WalletErrorReason::MalformedX509CertificateChain,
        pb::OpenId4VpErrorReason::WalletUnsupportedX509CertificateAlgorithm => WalletErrorReason::UnsupportedX509CertificateAlgorithm,
        pb::OpenId4VpErrorReason::WalletX509LeafKeyMismatch => WalletErrorReason::X509LeafKeyMismatch,
        pb::OpenId4VpErrorReason::WalletX509CertificateHashMismatch => WalletErrorReason::X509CertificateHashMismatch,
        pb::OpenId4VpErrorReason::WalletX509CertificateSanMismatch => WalletErrorReason::X509CertificateSanMismatch,
        pb::OpenId4VpErrorReason::WalletX509CertificatePathRejected => WalletErrorReason::X509CertificatePathRejected,
        pb::OpenId4VpErrorReason::WalletX509TrustEvidenceUnavailable => WalletErrorReason::X509TrustEvidenceUnavailable,
        pb::OpenId4VpErrorReason::WalletX509TrustEvidenceStale => WalletErrorReason::X509TrustEvidenceStale,
        pb::OpenId4VpErrorReason::WalletUnsupportedClientIdentifierMode => WalletErrorReason::UnsupportedClientIdentifierMode,
        pb::OpenId4VpErrorReason::WalletInvalidRequestObjectSignature => WalletErrorReason::InvalidRequestObjectSignature,
        pb::OpenId4VpErrorReason::WalletUnsupportedRequestObjectAlgorithm => WalletErrorReason::UnsupportedRequestObjectAlgorithm,
        pb::OpenId4VpErrorReason::WalletInvalidTransactionData => WalletErrorReason::InvalidTransactionData,
    })
}

/// Convert a public mdoc format error reason into its local protobuf reason.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn mdoc_error_reason_to_proto(value: MdocFormatErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemUnsupportedFeature, {
        MdocFormatErrorReason::InvalidDeviceResponse => pb::OpenId4VpErrorReason::MdocInvalidDeviceResponse,
        MdocFormatErrorReason::InvalidIssuerAuthentication => pb::OpenId4VpErrorReason::MdocInvalidIssuerAuthentication,
        MdocFormatErrorReason::InvalidDeviceAuthentication => pb::OpenId4VpErrorReason::MdocInvalidDeviceAuthentication,
        MdocFormatErrorReason::SessionTranscriptMismatch => pb::OpenId4VpErrorReason::MdocSessionTranscriptMismatch,
        MdocFormatErrorReason::DocumentTypeMismatch => pb::OpenId4VpErrorReason::MdocDocumentTypeMismatch,
        MdocFormatErrorReason::Expired => pb::OpenId4VpErrorReason::MdocExpired,
        MdocFormatErrorReason::UnsupportedOperation => pb::OpenId4VpErrorReason::MdocUnsupportedOperation,
    })
}

/// Convert a local protobuf reason back to a public mdoc format error reason.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn proto_to_mdoc_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<MdocFormatErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::MdocInvalidDeviceResponse => MdocFormatErrorReason::InvalidDeviceResponse,
        pb::OpenId4VpErrorReason::MdocInvalidIssuerAuthentication => MdocFormatErrorReason::InvalidIssuerAuthentication,
        pb::OpenId4VpErrorReason::MdocInvalidDeviceAuthentication => MdocFormatErrorReason::InvalidDeviceAuthentication,
        pb::OpenId4VpErrorReason::MdocSessionTranscriptMismatch => MdocFormatErrorReason::SessionTranscriptMismatch,
        pb::OpenId4VpErrorReason::MdocDocumentTypeMismatch => MdocFormatErrorReason::DocumentTypeMismatch,
        pb::OpenId4VpErrorReason::MdocExpired => MdocFormatErrorReason::Expired,
        pb::OpenId4VpErrorReason::MdocUnsupportedOperation => MdocFormatErrorReason::UnsupportedOperation,
    })
}

/// Convert a public ZK presentation format error reason into its local protobuf reason.
pub fn zk_error_reason_to_proto(value: ZkFormatErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::VerifierInvalidZkPresentation, {
        ZkFormatErrorReason::UnknownCircuit => pb::OpenId4VpErrorReason::ZkUnknownCircuit,
        ZkFormatErrorReason::UnsupportedCircuit => pb::OpenId4VpErrorReason::ZkUnsupportedCircuit,
        ZkFormatErrorReason::UnsupportedProofSuite => pb::OpenId4VpErrorReason::ZkUnsupportedProofSuite,
        ZkFormatErrorReason::InvalidPresentationEncoding => pb::OpenId4VpErrorReason::ZkInvalidPresentationEncoding,
        ZkFormatErrorReason::InvalidProof => pb::OpenId4VpErrorReason::ZkInvalidProof,
        ZkFormatErrorReason::BindingMismatch => pb::OpenId4VpErrorReason::ZkBindingMismatch,
        ZkFormatErrorReason::VerifierUnavailable => pb::OpenId4VpErrorReason::ZkVerifierUnavailable,
        ZkFormatErrorReason::CircuitVerificationMismatch => pb::OpenId4VpErrorReason::ZkCircuitVerificationMismatch,
    })
}

/// Convert a local protobuf reason back to a public ZK format error reason.
pub fn proto_to_zk_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<ZkFormatErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::ZkUnknownCircuit => ZkFormatErrorReason::UnknownCircuit,
        pb::OpenId4VpErrorReason::ZkUnsupportedCircuit => ZkFormatErrorReason::UnsupportedCircuit,
        pb::OpenId4VpErrorReason::ZkUnsupportedProofSuite => ZkFormatErrorReason::UnsupportedProofSuite,
        pb::OpenId4VpErrorReason::ZkInvalidPresentationEncoding => ZkFormatErrorReason::InvalidPresentationEncoding,
        pb::OpenId4VpErrorReason::ZkInvalidProof => ZkFormatErrorReason::InvalidProof,
        pb::OpenId4VpErrorReason::ZkBindingMismatch => ZkFormatErrorReason::BindingMismatch,
        pb::OpenId4VpErrorReason::ZkVerifierUnavailable => ZkFormatErrorReason::VerifierUnavailable,
        pb::OpenId4VpErrorReason::ZkCircuitVerificationMismatch => ZkFormatErrorReason::CircuitVerificationMismatch,
    })
}

/// Convert a public Digital Credentials API error reason into its local protobuf reason.
pub fn dc_api_error_reason_to_proto(value: DcApiErrorReason) -> pb::OpenId4VpErrorReason {
    to_proto!(value, pb::OpenId4VpErrorReason::ProblemInvalidRequest, {
        DcApiErrorReason::EmptyValue => pb::OpenId4VpErrorReason::DcApiEmptyValue,
        DcApiErrorReason::EmptyRequestSet => pb::OpenId4VpErrorReason::DcApiEmptyRequestSet,
        DcApiErrorReason::InvalidProtocol => pb::OpenId4VpErrorReason::DcApiInvalidProtocol,
        DcApiErrorReason::HandoverEncodingFailed => pb::OpenId4VpErrorReason::DcApiHandoverEncodingFailed,
        DcApiErrorReason::InvalidRequestObject => pb::OpenId4VpErrorReason::DcApiInvalidRequestObject,
        DcApiErrorReason::RequestObjectTooLarge => pb::OpenId4VpErrorReason::DcApiRequestObjectTooLarge,
        DcApiErrorReason::TooManyRequestObjectSignatures => pb::OpenId4VpErrorReason::DcApiTooManyRequestObjectSignatures,
    })
}

/// Convert a local protobuf reason back to a public Digital Credentials API error reason.
pub fn proto_to_dc_api_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<DcApiErrorReason, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::DcApiEmptyValue => DcApiErrorReason::EmptyValue,
        pb::OpenId4VpErrorReason::DcApiEmptyRequestSet => DcApiErrorReason::EmptyRequestSet,
        pb::OpenId4VpErrorReason::DcApiInvalidProtocol => DcApiErrorReason::InvalidProtocol,
        pb::OpenId4VpErrorReason::DcApiHandoverEncodingFailed => DcApiErrorReason::HandoverEncodingFailed,
        pb::OpenId4VpErrorReason::DcApiInvalidRequestObject => DcApiErrorReason::InvalidRequestObject,
        pb::OpenId4VpErrorReason::DcApiRequestObjectTooLarge => DcApiErrorReason::RequestObjectTooLarge,
        pb::OpenId4VpErrorReason::DcApiTooManyRequestObjectSignatures => DcApiErrorReason::TooManyRequestObjectSignatures,
    })
}

/// Convert a proto-codec error into its local protobuf reason.
pub fn proto_error_reason_to_proto(value: OpenId4VpProtoError) -> pb::OpenId4VpErrorReason {
    match value {
        OpenId4VpProtoError::Decode => pb::OpenId4VpErrorReason::ProtoDecode,
        OpenId4VpProtoError::Encode => pb::OpenId4VpErrorReason::ProtoEncode,
        OpenId4VpProtoError::MissingField => pb::OpenId4VpErrorReason::ProtoMissingField,
        OpenId4VpProtoError::InvalidEnumValue => pb::OpenId4VpErrorReason::ProtoInvalidEnumValue,
        OpenId4VpProtoError::InvalidField => pb::OpenId4VpErrorReason::ProtoInvalidField,
        OpenId4VpProtoError::JsonSerialize => pb::OpenId4VpErrorReason::ProtoJsonSerialize,
        OpenId4VpProtoError::JsonDeserialize => pb::OpenId4VpErrorReason::ProtoJsonDeserialize,
        OpenId4VpProtoError::JsonTooLarge => pb::OpenId4VpErrorReason::ProtoJsonTooLarge,
        OpenId4VpProtoError::JsonNestingTooDeep => {
            pb::OpenId4VpErrorReason::ProtoJsonNestingTooDeep
        }
        OpenId4VpProtoError::JsonDuplicateKey => pb::OpenId4VpErrorReason::ProtoJsonDuplicateKey,
    }
}

/// Convert a local protobuf reason back to a proto-codec error.
pub fn proto_to_proto_error_reason(
    value: pb::OpenId4VpErrorReason,
) -> Result<OpenId4VpProtoError, OpenId4VpProtoError> {
    from_proto!(value, {
        pb::OpenId4VpErrorReason::ProtoDecode => OpenId4VpProtoError::Decode,
        pb::OpenId4VpErrorReason::ProtoEncode => OpenId4VpProtoError::Encode,
        pb::OpenId4VpErrorReason::ProtoMissingField => OpenId4VpProtoError::MissingField,
        pb::OpenId4VpErrorReason::ProtoInvalidEnumValue => OpenId4VpProtoError::InvalidEnumValue,
        pb::OpenId4VpErrorReason::ProtoInvalidField => OpenId4VpProtoError::InvalidField,
        pb::OpenId4VpErrorReason::ProtoJsonSerialize => OpenId4VpProtoError::JsonSerialize,
        pb::OpenId4VpErrorReason::ProtoJsonDeserialize => OpenId4VpProtoError::JsonDeserialize,
        pb::OpenId4VpErrorReason::ProtoJsonTooLarge => OpenId4VpProtoError::JsonTooLarge,
        pb::OpenId4VpErrorReason::ProtoJsonNestingTooDeep => OpenId4VpProtoError::JsonNestingTooDeep,
        pb::OpenId4VpErrorReason::ProtoJsonDuplicateKey => OpenId4VpProtoError::JsonDuplicateKey,
    })
}

/// Convert a raw protobuf enum discriminant into a typed OpenID4VP reason.
pub fn error_reason_from_i32(value: i32) -> Result<pb::OpenId4VpErrorReason, OpenId4VpProtoError> {
    pb::OpenId4VpErrorReason::from_i32(value).ok_or(OpenId4VpProtoError::InvalidEnumValue)
}

/// Convert a generated enum value into a typed OpenID4VP reason.
pub fn error_reason_from_enum_value(
    value: EnumValue<pb::OpenId4VpErrorReason>,
) -> Result<pb::OpenId4VpErrorReason, OpenId4VpProtoError> {
    value
        .as_known()
        .ok_or(OpenId4VpProtoError::InvalidEnumValue)
}

/// Wrap a local OpenID4VP reason in the shared identity-stack error envelope.
pub fn identity_stack_error_from_reason(
    reason: pb::OpenId4VpErrorReason,
    correlation_id: Option<&str>,
) -> IdentityStackError {
    IdentityStackError {
        domain: OPENID4VP_DOMAIN.into(),
        reason_code: error_reason_code(reason),
        correlation_id: correlation_id.map_or_else(String::new, str::to_owned),
        ..IdentityStackError::default()
    }
}

/// Extract a local OpenID4VP reason from a shared identity-stack error envelope.
pub fn error_reason_from_identity_stack_error(
    error: &IdentityStackError,
) -> Result<pb::OpenId4VpErrorReason, OpenId4VpProtoError> {
    if error.domain.as_known() != Some(OPENID4VP_DOMAIN) {
        return Err(OpenId4VpProtoError::InvalidEnumValue);
    }
    let reason_code =
        i32::try_from(error.reason_code).map_err(|_| OpenId4VpProtoError::InvalidEnumValue)?;
    error_reason_from_i32(reason_code)
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
