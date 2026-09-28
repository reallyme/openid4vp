// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::WalletTransactionDataPolicy;
use crate::{
    validate_client_metadata_reference_binding, validate_response_endpoint_binding,
    validate_verifier_attestation_binding,
    verifier_attestation::validate_verifier_attestation_claim_binding,
    VerifiedClientIdentifierBinding, VerifiedClientMetadataReference, VerifiedVerifierAttestation,
    VerifiedX509CertificateBinding,
};
use crate::{
    AuthorizationRequestTransport, WalletError, WalletErrorReason, WalletInvocationContext,
};

/// Verified signed wallet request with parsed OpenID4VP claims.
///
/// The request is deliberately opaque. Wallet operations that can disclose a
/// credential or emit a response accept this receipt rather than a raw
/// [`AuthorizationRequestObject`], so validation cannot be bypassed by
/// constructing protocol DTOs directly.
///
/// ```compile_fail
/// # use reallyme_openid4vp_types::AuthorizationRequestObject;
/// # use reallyme_openid4vp_wallet::VerifiedWalletRequest;
/// # fn forged(request: AuthorizationRequestObject) {
/// let _ = VerifiedWalletRequest { request };
/// # }
/// ```
#[derive(Clone, PartialEq)]
pub struct VerifiedWalletRequest {
    /// Parsed Authorization Request Object.
    request: AuthorizationRequestObject,
}

pub(crate) mod sealed {
    use reallyme_openid4vp_types::AuthorizationRequestObject;

    pub trait SealedWalletRequest {
        fn authorization_request(&self) -> &AuthorizationRequestObject;
    }
}

/// Opaque authorization-request receipt accepted by wallet disclosure APIs.
///
/// Only this crate's signed and unsigned verification boundaries implement the
/// sealed trait. Applications can inspect a verified request but cannot turn a
/// raw request DTO into authorization to select or disclose credentials.
pub trait WalletAuthorizationRequest: sealed::SealedWalletRequest {
    /// Borrow the request that was covered by this verification receipt.
    #[must_use]
    fn request(&self) -> &AuthorizationRequestObject {
        self.authorization_request()
    }
}

impl sealed::SealedWalletRequest for VerifiedWalletRequest {
    fn authorization_request(&self) -> &AuthorizationRequestObject {
        &self.request
    }
}

impl WalletAuthorizationRequest for VerifiedWalletRequest {}

/// Wallet capability policy for final-spec Client Identifier Prefix modes.
///
/// OpenID4VP 1.0 Final Section 5.9.2 assigns an unprefixed identifier to a
/// pre-registered client. This crate deliberately does not advertise or
/// accept that mode until an atomic registration receipt API is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletClientIdentifierPolicy {
    pre_registered_supported: bool,
}

/// Temporal policy applied consistently by signature verification and the
/// wallet's post-verification claim validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WalletRequestTemporalPolicy {
    max_future_iat_skew_seconds: u64,
}

impl WalletRequestTemporalPolicy {
    const DEFAULT_MAX_FUTURE_IAT_SKEW_SECONDS: u64 = 60;

    const fn production() -> Self {
        Self {
            max_future_iat_skew_seconds: Self::DEFAULT_MAX_FUTURE_IAT_SKEW_SECONDS,
        }
    }

    #[cfg(feature = "jose")]
    const fn from_max_future_iat_skew_seconds(max_future_iat_skew_seconds: u64) -> Self {
        Self {
            max_future_iat_skew_seconds,
        }
    }
}

impl WalletClientIdentifierPolicy {
    /// Return the production capability policy.
    pub const fn production() -> Self {
        Self {
            pre_registered_supported: false,
        }
    }

    /// Report whether unprefixed pre-registered clients are supported.
    #[must_use]
    pub const fn pre_registered_supported(self) -> bool {
        self.pre_registered_supported
    }
}

impl Default for WalletClientIdentifierPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl fmt::Debug for VerifiedWalletRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedWalletRequest(<redacted>)")
    }
}

impl Zeroize for VerifiedWalletRequest {
    fn zeroize(&mut self) {
        self.request.zeroize();
    }
}

impl Drop for VerifiedWalletRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedWalletRequest {}

/// Wallet-side Request Object verifier.
///
/// Implementations verify compact JWT syntax, JWS/JWE policy, signature,
/// `kid` to verifier key binding, and claim decoding using injected trust
/// material. Network fetching belongs outside this trait.
pub trait RequestObjectSignatureVerifier: Send + Sync {
    /// Verify a compact Request Object JWT and return claims and evidence atomically.
    ///
    /// The result must describe the exact JWT supplied to this call. This is a
    /// required method so adapters cannot accidentally verify one value and
    /// resolve signer evidence through an uncorrelated second lookup.
    fn verify_request_object(
        &self,
        jwt: &str,
        invocation: &WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError>;
}

/// Atomic output from verification of one exact signed Request Object.
pub struct VerifiedRequestObject {
    request: AuthorizationRequestObject,
    evidence: WalletRequestTrustEvidence,
    temporal_policy: WalletRequestTemporalPolicy,
}

impl VerifiedRequestObject {
    // The constructor is consumed by optional JOSE adapters and crate-local
    // verifier fixtures; the default feature set intentionally has no adapter.
    #[allow(dead_code)]
    pub(crate) const fn new(
        request: AuthorizationRequestObject,
        evidence: WalletRequestTrustEvidence,
    ) -> Self {
        Self {
            request,
            evidence,
            temporal_policy: WalletRequestTemporalPolicy::production(),
        }
    }

    #[cfg(feature = "jose")]
    pub(crate) const fn new_with_temporal_policy(
        request: AuthorizationRequestObject,
        evidence: WalletRequestTrustEvidence,
        max_future_iat_skew_seconds: u64,
    ) -> Self {
        Self {
            request,
            evidence,
            temporal_policy: WalletRequestTemporalPolicy::from_max_future_iat_skew_seconds(
                max_future_iat_skew_seconds,
            ),
        }
    }

    fn into_parts(
        self,
    ) -> (
        AuthorizationRequestObject,
        WalletRequestTrustEvidence,
        WalletRequestTemporalPolicy,
    ) {
        (self.request, self.evidence, self.temporal_policy)
    }

    pub(crate) fn client_identifier(&self) -> Option<&ClientIdentifier> {
        self.request.client_id.as_ref()
    }
}

impl fmt::Debug for VerifiedRequestObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRequestObject(<redacted>)")
    }
}

// Both fields own zeroizing values; Rust's field drop glue performs the wipe.
impl ZeroizeOnDrop for VerifiedRequestObject {}

/// Host-supplied trust evidence for wallet Request Object validation.
#[derive(Default)]
pub struct WalletRequestTrustEvidence {
    /// DID verification-method or federation entity/key binding.
    pub(crate) client_identifier_binding: Option<VerifiedClientIdentifierBinding>,
    /// Verified Verifier Attestation JWT summary.
    pub(crate) verifier_attestation: Option<VerifiedVerifierAttestation>,
    /// Fresh trusted metadata resolved from a metadata reference extension.
    pub(crate) client_metadata_reference: Option<VerifiedClientMetadataReference>,
    /// Verified leaf-certificate evidence for an X.509 Request Object signer.
    pub(crate) x509_certificate_binding: Option<VerifiedX509CertificateBinding>,
}

impl fmt::Debug for WalletRequestTrustEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletRequestTrustEvidence")
            .field(
                "has_client_identifier_binding",
                &self.client_identifier_binding.is_some(),
            )
            .field(
                "has_verifier_attestation",
                &self.verifier_attestation.is_some(),
            )
            .field(
                "has_client_metadata_reference",
                &self.client_metadata_reference.is_some(),
            )
            .field(
                "has_x509_certificate_binding",
                &self.x509_certificate_binding.is_some(),
            )
            .finish()
    }
}

impl Zeroize for WalletRequestTrustEvidence {
    fn zeroize(&mut self) {
        self.client_identifier_binding.zeroize();
        self.verifier_attestation.zeroize();
        self.client_metadata_reference.zeroize();
        self.x509_certificate_binding.zeroize();
    }
}

impl Drop for WalletRequestTrustEvidence {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for WalletRequestTrustEvidence {}

/// Verify and validate a signed Request Object for wallet processing.
pub fn verify_signed_request_object(
    verifier: &impl RequestObjectSignatureVerifier,
    jwt: &str,
    invocation: &WalletInvocationContext,
    now_unix: u64,
) -> Result<VerifiedWalletRequest, WalletError> {
    verify_signed_request_object_with_transaction_data_policy(
        verifier,
        jwt,
        invocation,
        now_unix,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Verify a signed Request Object with an explicit transaction-data allowlist.
pub fn verify_signed_request_object_with_transaction_data_policy(
    verifier: &impl RequestObjectSignatureVerifier,
    jwt: &str,
    invocation: &WalletInvocationContext,
    now_unix: u64,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<VerifiedWalletRequest, WalletError> {
    let verified = verifier.verify_request_object(jwt, invocation, now_unix)?;
    finish_verified_request_object_with_transaction_data_policy(
        verified,
        invocation,
        now_unix,
        transaction_data_policy,
    )
}

pub(crate) fn finish_verified_request_object_with_transaction_data_policy(
    verified: VerifiedRequestObject,
    invocation: &WalletInvocationContext,
    now_unix: u64,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<VerifiedWalletRequest, WalletError> {
    let (request, evidence, temporal_policy) = verified.into_parts();
    validate_client_identifier_trust_binding(&request, &evidence)?;
    validate_wallet_request_object_with_evidence_and_policies(
        &request,
        invocation.expected_origin(),
        now_unix,
        &evidence,
        temporal_policy,
        transaction_data_policy,
    )?;
    Ok(VerifiedWalletRequest { request })
}

/// Verify a by-value Request Object transport and enforce transport bindings.
pub fn verify_request_transport(
    verifier: &impl RequestObjectSignatureVerifier,
    transport: AuthorizationRequestTransport,
    invocation: &WalletInvocationContext,
    now_unix: u64,
) -> Result<VerifiedWalletRequest, WalletError> {
    verify_request_transport_with_transaction_data_policy(
        verifier,
        transport,
        invocation,
        now_unix,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Verify request transport bindings with an explicit transaction-data allowlist.
pub fn verify_request_transport_with_transaction_data_policy(
    verifier: &impl RequestObjectSignatureVerifier,
    transport: AuthorizationRequestTransport,
    invocation: &WalletInvocationContext,
    now_unix: u64,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<VerifiedWalletRequest, WalletError> {
    let AuthorizationRequestTransport::RequestJwt {
        jwt,
        expected_client_id,
        expected_wallet_nonce,
    } = &transport
    else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    };

    let verified = verifier.verify_request_object(jwt, invocation, now_unix)?;
    let (request, evidence, temporal_policy) = verified.into_parts();
    validate_transport_client_id_binding(expected_client_id.as_deref(), &request)?;
    validate_transport_wallet_nonce_binding(expected_wallet_nonce.as_deref(), &request)?;
    validate_wallet_request_object_with_evidence_and_policies(
        &request,
        invocation.expected_origin(),
        now_unix,
        &evidence,
        temporal_policy,
        transaction_data_policy,
    )?;
    Ok(VerifiedWalletRequest { request })
}

include!("jar_validation.rs");

#[cfg(test)]
#[path = "jar_tests.rs"]
mod tests;
