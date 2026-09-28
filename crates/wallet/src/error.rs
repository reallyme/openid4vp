// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::{ProblemDetails, ProblemKind};
use thiserror::Error;

/// Wallet-side OpenID4VP error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP wallet error: {reason:?}")]
pub struct WalletError {
    reason: WalletErrorReason,
}

impl WalletError {
    /// Build a wallet error from a stable reason.
    pub const fn new(reason: WalletErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> WalletErrorReason {
        self.reason
    }
}

/// Stable wallet error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletErrorReason {
    /// Incoming authorization request transport could not be parsed.
    InvalidAuthorizationRequestTransport,
    /// A security-sensitive authorization request parameter appeared twice.
    DuplicateAuthorizationRequestParameter,
    /// Both `request` and `request_uri` were supplied.
    ConflictingRequestObjectParameters,
    /// A wallet-generated `wallet_nonce` was required by a downstream adapter.
    MissingWalletNonce,
    /// `wallet_nonce` was supplied for a transport where it is not valid.
    UnexpectedWalletNonce,
    /// `request_uri_method` is not a supported final-spec value.
    UnsupportedRequestUriMethod,
    /// Transport-level `client_id` does not match the signed Request Object.
    TransportClientIdentifierMismatch,
    /// Response endpoint host does not match the signed client identifier.
    ResponseEndpointClientIdentifierMismatch,
    /// An X.509 client identifier was used without an `x5c` JOSE header.
    MissingX509CertificateChain,
    /// The `x5c` JOSE header or a certificate in it is malformed or exceeds policy.
    MalformedX509CertificateChain,
    /// The certificate signature or public-key algorithm is not supported by policy.
    UnsupportedX509CertificateAlgorithm,
    /// The JWS verification key is not the public key of the `x5c` leaf certificate.
    X509LeafKeyMismatch,
    /// The `x509_hash` client identifier does not match the leaf certificate.
    X509CertificateHashMismatch,
    /// The `x509_san_dns` client identifier does not match a leaf DNS SAN.
    X509CertificateSanMismatch,
    /// Certificate path or profile validation definitively rejected the signer.
    X509CertificatePathRejected,
    /// Required certificate trust infrastructure could not reach a decision.
    X509TrustEvidenceUnavailable,
    /// Certificate trust evidence is outside its evaluated validity interval.
    X509TrustEvidenceStale,
    /// POST `request_uri` wallet_nonce does not match the signed Request Object.
    TransportWalletNonceMismatch,
    /// Request Object JWT exceeds policy.
    RequestObjectTooLarge,
    /// Request Object signature or claims failed verification.
    InvalidRequestObject,
    /// Request Object signature or resolver-selected verification key did not verify.
    InvalidRequestObjectSignature,
    /// Request Object JOSE algorithm is absent, unsupported, or violates key policy.
    UnsupportedRequestObjectAlgorithm,
    /// The Request Object expired.
    RequestObjectExpired,
    /// The Request Object was issued in the future.
    RequestObjectIssuedInFuture,
    /// Signed request did not bind a final-spec client_id prefix.
    InvalidClientIdentifierPrefix,
    /// A valid final-spec client identifier mode is disabled by wallet policy.
    UnsupportedClientIdentifierMode,
    /// DID or federation trust evidence did not bind the claimed subject and key.
    InvalidClientIdentifierTrustBinding,
    /// Verifier attestation evidence was absent or failed request binding.
    InvalidVerifierAttestation,
    /// Referenced verifier metadata was absent, stale, or not bound to the request.
    InvalidMetadataReference,
    /// Digital Credentials API request origin is not listed in `expected_origins`.
    ExpectedOriginMismatch,
    /// Browser platform origin evidence is absent, malformed, or used on the wrong transport.
    InvalidPlatformOrigin,
    /// Transaction data is empty or uses a type not explicitly enabled by wallet policy.
    InvalidTransactionData,
    /// The wallet does not support the requested feature.
    UnsupportedFeature,
    /// ZK derivation failed or the prover was unavailable.
    ZkDerivationFailed,
    /// A response was requested without any selected presentation.
    MissingSelectedPresentation,
    /// A selected presentation referenced no verified DCQL credential query.
    UnknownSelectedCredentialQuery,
    /// A single-valued DCQL query received more than one presentation.
    SelectedPresentationCardinalityMismatch,
    /// The selected presentations do not satisfy every required DCQL query or set.
    UnsatisfiedRequiredCredentialQuery,
    /// Transaction-data hashes were absent, incomplete, or unexpected.
    InvalidTransactionDataResponse,
    /// Encrypted-response metadata or a usable recipient key was absent.
    MissingResponseEncryptionMetadata,
    /// The verifier requested an encryption algorithm outside wallet policy.
    UnsupportedResponseEncryptionAlgorithm,
    /// A candidate response-encryption JWK was malformed or unsafe.
    InvalidResponseEncryptionKey,
    /// Authorization Response serialization, randomness, or encryption failed.
    ResponseEncryptionFailed,
}

impl From<WalletError> for ProblemDetails {
    fn from(error: WalletError) -> Self {
        let kind = match error.reason() {
            WalletErrorReason::InvalidClientIdentifierPrefix
            | WalletErrorReason::UnsupportedClientIdentifierMode => {
                ProblemKind::InvalidClientIdentifier
            }
            WalletErrorReason::ConflictingRequestObjectParameters
            | WalletErrorReason::DuplicateAuthorizationRequestParameter
            | WalletErrorReason::InvalidAuthorizationRequestTransport
            | WalletErrorReason::InvalidTransactionData
            | WalletErrorReason::MissingWalletNonce
            | WalletErrorReason::ResponseEndpointClientIdentifierMismatch
            | WalletErrorReason::RequestObjectTooLarge
            | WalletErrorReason::TransportClientIdentifierMismatch
            | WalletErrorReason::TransportWalletNonceMismatch
            | WalletErrorReason::UnexpectedWalletNonce
            | WalletErrorReason::UnsupportedRequestUriMethod => ProblemKind::InvalidRequest,
            WalletErrorReason::ExpectedOriginMismatch
            | WalletErrorReason::InvalidClientIdentifierTrustBinding
            | WalletErrorReason::InvalidPlatformOrigin
            | WalletErrorReason::InvalidMetadataReference
            | WalletErrorReason::InvalidRequestObject
            | WalletErrorReason::InvalidRequestObjectSignature
            | WalletErrorReason::InvalidVerifierAttestation
            | WalletErrorReason::MalformedX509CertificateChain
            | WalletErrorReason::MissingX509CertificateChain
            | WalletErrorReason::RequestObjectExpired
            | WalletErrorReason::RequestObjectIssuedInFuture
            | WalletErrorReason::MissingResponseEncryptionMetadata
            | WalletErrorReason::UnsupportedResponseEncryptionAlgorithm
            | WalletErrorReason::InvalidResponseEncryptionKey
            | WalletErrorReason::UnsupportedRequestObjectAlgorithm
            | WalletErrorReason::UnsupportedX509CertificateAlgorithm
            | WalletErrorReason::X509CertificateHashMismatch
            | WalletErrorReason::X509CertificatePathRejected
            | WalletErrorReason::X509CertificateSanMismatch
            | WalletErrorReason::X509LeafKeyMismatch
            | WalletErrorReason::X509TrustEvidenceStale
            | WalletErrorReason::X509TrustEvidenceUnavailable => ProblemKind::InvalidRequestObject,
            WalletErrorReason::UnsupportedFeature => ProblemKind::UnsupportedFeature,
            WalletErrorReason::UnsatisfiedRequiredCredentialQuery => {
                ProblemKind::UnsatisfiedDcqlQuery
            }
            WalletErrorReason::InvalidTransactionDataResponse
            | WalletErrorReason::MissingSelectedPresentation
            | WalletErrorReason::SelectedPresentationCardinalityMismatch
            | WalletErrorReason::UnknownSelectedCredentialQuery
            | WalletErrorReason::ResponseEncryptionFailed
            | WalletErrorReason::ZkDerivationFailed => ProblemKind::WalletUnavailable,
        };
        Self::from_kind(kind)
    }
}
