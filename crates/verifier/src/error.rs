// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Verifier boundary error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP verifier error: {reason:?}")]
pub struct VerifierError {
    reason: VerifierErrorReason,
}

impl VerifierError {
    /// Build a verifier error from a stable reason.
    pub const fn new(reason: VerifierErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> VerifierErrorReason {
        self.reason
    }
}

/// Stable verifier error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierErrorReason {
    /// Request Object signature or claims failed verification.
    InvalidRequestObject,
    /// Request Object issuer is absent.
    MissingIssuer,
    /// Request Object audience is absent.
    MissingAudience,
    /// Request Object client identifier is absent.
    MissingClientIdentifier,
    /// Request Object nonce is absent or empty.
    MissingNonce,
    /// Request Object issuer does not match the final client identifier.
    IssuerClientIdentifierMismatch,
    /// Request Object expiration is absent.
    MissingExpiration,
    /// Request Object issued-at timestamp is absent.
    MissingIssuedAt,
    /// Trusted clock was unavailable for temporal Request Object validation.
    ClockUnavailable,
    /// Request Object is expired.
    RequestObjectExpired,
    /// Request Object is issued in the future.
    RequestObjectIssuedInFuture,
    /// Request Object lifetime is longer than verifier policy allows.
    RequestObjectLifetimeTooLong,
    /// Request Object reference is not HTTPS.
    InvalidRequestUri,
    /// Request binding is missing a required value.
    InvalidBinding,
    /// Holder-binding proof is missing a required claim.
    MissingHolderBindingClaim,
    /// Holder-binding proof audience does not match request binding.
    HolderBindingAudienceMismatch,
    /// Holder-binding proof nonce does not match request binding.
    HolderBindingNonceMismatch,
    /// Holder-binding proof expired or outlives request binding.
    HolderBindingExpired,
    /// Credential status information cryptographically proves the credential is revoked.
    CredentialRevoked,
    /// Credential status information was present but malformed, unauthenticated, or inconsistent.
    InvalidCredentialStatus,
    /// Credential status information was required by verifier policy but could not be resolved.
    CredentialStatusUnavailable,
    /// Credential validity claims were malformed or outside their accepted time window.
    InvalidCredentialValidity,
    /// Request binding has expired.
    BindingExpired,
    /// Session state could not be found.
    SessionNotFound,
    /// Session state does not match the response.
    SessionMismatch,
    /// Authorization Response contained an empty `vp_token` object.
    EmptyVpToken,
    /// Authorization Response contained an empty presentation list.
    EmptyPresentationList,
    /// Authorization Response `vp_token` keys do not match the session DCQL query ids.
    VpTokenQueryMismatch,
    /// Authorization Response returned multiple presentations for a `multiple:false` query.
    VpTokenCardinalityMismatch,
    /// Authorization Response contained a presentation format unsupported by configured verifier.
    UnsupportedFormat,
    /// ZK presentation failed format, binding, policy, or proof verification.
    InvalidZkPresentation,
}
