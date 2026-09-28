// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

pub use reallyme_openid4vp_types::REQUEST_OBJECT_MEDIA_TYPE;
use reallyme_openid4vp_types::{
    classify_request_object_jwt, AuthorizationRequestObject, RequestObjectJwtKind,
};

use crate::{VerifierError, VerifierErrorReason, MIN_SESSION_BINDING_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum accepted compact Request Object JWT size.
pub const MAX_COMPACT_REQUEST_OBJECT_JWT_BYTES: usize = 64 * 1024;

/// Compact serialized JWT Request Object.
#[derive(Clone, PartialEq, Eq)]
pub struct CompactJwt(String);

impl fmt::Debug for CompactJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompactJwt")
            .field("byte_len", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for CompactJwt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CompactJwt {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CompactJwt {}

impl CompactJwt {
    /// Construct a compact JWT after minimal structural validation.
    pub fn new(value: String) -> Result<Self, VerifierError> {
        if value.len() > MAX_COMPACT_REQUEST_OBJECT_JWT_BYTES {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidRequestObject,
            ));
        }
        let kind = classify_request_object_jwt(&value)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRequestObject))?;
        if kind != RequestObjectJwtKind::Signed {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidRequestObject,
            ));
        }
        Ok(Self(value))
    }

    /// Return the compact JWT string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Signing boundary for RFC 9101 Request Objects.
///
/// Implementations belong in adapters backed by `reallyme-crypto` JOSE/COSE
/// primitives and injected key material. The protocol crate keeps this trait
/// network-free and side-effect-free so Request Object assembly stays auditable.
pub trait RequestObjectSigner: Send + Sync {
    /// Sign an OpenID4VP Authorization Request Object as a compact JWT.
    fn sign_request_object(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<CompactJwt, VerifierError>;
}

/// Request Object claim validation policy derived from RFC 9101 processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JarPolicy {
    /// Require an issuer claim.
    pub require_issuer: bool,
    /// Require issuer to equal the final-prefixed client identifier.
    pub require_issuer_matches_client_id: bool,
    /// Require an audience claim.
    pub require_audience: bool,
    /// Require an issued-at claim.
    pub require_issued_at: bool,
    /// Require an expiration claim.
    pub require_expiration: bool,
    /// Maximum accepted Request Object lifetime, in seconds.
    pub max_lifetime_secs: Option<u64>,
    /// Accepted clock skew for issued-at values in the future.
    pub issued_at_future_skew_secs: u64,
}

impl Default for JarPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS: u64 = 300;
        const DEFAULT_IAT_FUTURE_SKEW_SECS: u64 = 60;
        Self {
            require_issuer: true,
            require_issuer_matches_client_id: true,
            require_audience: true,
            require_issued_at: true,
            require_expiration: true,
            max_lifetime_secs: Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS),
            issued_at_future_skew_secs: DEFAULT_IAT_FUTURE_SKEW_SECS,
        }
    }
}

/// Build and sign a Request Object through an injected signer.
pub fn build_signed_request_object(
    signer: &impl RequestObjectSigner,
    request: &AuthorizationRequestObject,
    now_unix: u64,
) -> Result<CompactJwt, VerifierError> {
    validate_jar_claims_for_signing(request, now_unix, JarPolicy::default())?;
    signer.sign_request_object(request)
}

/// Validate Request Object claims immediately before signing.
pub fn validate_jar_claims_for_signing(
    request: &AuthorizationRequestObject,
    now_unix: u64,
    policy: JarPolicy,
) -> Result<(), VerifierError> {
    validate_jar_claims(request, now_unix, policy)
}

/// Validate RFC 9101 Request Object temporal and identity claims.
///
/// Signature verification, JWT header algorithm policy, and `kid` to client
/// binding are intentionally delegated to `RequestObjectSigner` and
/// `RequestObjectVerifier` implementations backed by the JOSE stack.
pub fn validate_jar_claims(
    request: &AuthorizationRequestObject,
    now_unix: u64,
    policy: JarPolicy,
) -> Result<(), VerifierError> {
    let temporal = validate_jar_claims_without_clock(request, policy)?;
    if now_unix == 0 {
        return Err(VerifierError::new(VerifierErrorReason::ClockUnavailable));
    }

    let Some(exp) = temporal.expiration_unix else {
        return Ok(());
    };

    if exp <= now_unix {
        return Err(VerifierError::new(
            VerifierErrorReason::RequestObjectExpired,
        ));
    }

    if let Some(iat) = temporal.issued_at_unix {
        let Some(max_iat) = now_unix.checked_add(policy.issued_at_future_skew_secs) else {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        };
        if iat > max_iat {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct JarTemporalClaims {
    expiration_unix: Option<u64>,
    issued_at_unix: Option<u64>,
}

fn validate_jar_claims_without_clock(
    request: &AuthorizationRequestObject,
    policy: JarPolicy,
) -> Result<JarTemporalClaims, VerifierError> {
    if policy.require_issuer && request.iss.as_deref().is_none_or(str::is_empty) {
        return Err(VerifierError::new(VerifierErrorReason::MissingIssuer));
    }

    if policy.require_audience && request.aud.as_ref().is_none_or(Vec::is_empty) {
        return Err(VerifierError::new(VerifierErrorReason::MissingAudience));
    }

    let Some(client_id) = request.client_id.as_ref() else {
        return Err(VerifierError::new(
            VerifierErrorReason::MissingClientIdentifier,
        ));
    };

    if request.nonce.len() < MIN_SESSION_BINDING_BYTES {
        return Err(VerifierError::new(VerifierErrorReason::MissingNonce));
    }

    if request
        .state
        .as_ref()
        .is_some_and(|state| state.len() < MIN_SESSION_BINDING_BYTES)
    {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }

    if policy.require_issuer_matches_client_id {
        let Some(issuer) = request.iss.as_deref() else {
            return Err(VerifierError::new(VerifierErrorReason::MissingIssuer));
        };
        if issuer != client_id.to_wire_value() {
            return Err(VerifierError::new(
                VerifierErrorReason::IssuerClientIdentifierMismatch,
            ));
        }
    }

    if policy.require_issued_at && request.iat.is_none() {
        return Err(VerifierError::new(VerifierErrorReason::MissingIssuedAt));
    }

    let Some(exp) = request.exp else {
        if policy.require_expiration {
            return Err(VerifierError::new(VerifierErrorReason::MissingExpiration));
        }
        return Ok(JarTemporalClaims {
            expiration_unix: None,
            issued_at_unix: request.iat,
        });
    };

    let iat = request.iat;

    if let Some(iat) = iat {
        if exp < iat {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        }
    }

    if let Some(max_lifetime_secs) = policy.max_lifetime_secs {
        let Some(iat) = iat else {
            return Ok(JarTemporalClaims {
                expiration_unix: Some(exp),
                issued_at_unix: None,
            });
        };
        let Some(lifetime) = exp.checked_sub(iat) else {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectIssuedInFuture,
            ));
        };
        if lifetime > max_lifetime_secs {
            return Err(VerifierError::new(
                VerifierErrorReason::RequestObjectLifetimeTooLong,
            ));
        }
    }

    Ok(JarTemporalClaims {
        expiration_unix: Some(exp),
        issued_at_unix: iat,
    })
}

impl From<VerifierError> for reallyme_openid4vp_types::ProblemDetails {
    fn from(error: VerifierError) -> Self {
        let kind = match error.reason() {
            VerifierErrorReason::MissingIssuer
            | VerifierErrorReason::MissingAudience
            | VerifierErrorReason::MissingClientIdentifier
            | VerifierErrorReason::MissingExpiration
            | VerifierErrorReason::MissingIssuedAt
            | VerifierErrorReason::MissingNonce
            | VerifierErrorReason::ClockUnavailable
            | VerifierErrorReason::IssuerClientIdentifierMismatch
            | VerifierErrorReason::RequestObjectExpired
            | VerifierErrorReason::RequestObjectIssuedInFuture
            | VerifierErrorReason::RequestObjectLifetimeTooLong
            | VerifierErrorReason::InvalidRequestUri
            | VerifierErrorReason::InvalidRequestObject => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequestObject
            }
            VerifierErrorReason::BindingExpired => {
                reallyme_openid4vp_types::ProblemKind::BindingExpired
            }
            VerifierErrorReason::SessionNotFound => {
                reallyme_openid4vp_types::ProblemKind::SessionNotFound
            }
            VerifierErrorReason::SessionMismatch => {
                reallyme_openid4vp_types::ProblemKind::SessionMismatch
            }
            VerifierErrorReason::EmptyPresentationList
            | VerifierErrorReason::EmptyVpToken
            | VerifierErrorReason::InvalidBinding
            | VerifierErrorReason::CredentialRevoked
            | VerifierErrorReason::InvalidCredentialStatus
            | VerifierErrorReason::CredentialStatusUnavailable
            | VerifierErrorReason::InvalidCredentialValidity
            | VerifierErrorReason::InvalidZkPresentation
            | VerifierErrorReason::VpTokenCardinalityMismatch
            | VerifierErrorReason::VpTokenQueryMismatch => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequest
            }
            VerifierErrorReason::UnsupportedFormat => {
                reallyme_openid4vp_types::ProblemKind::UnsupportedFeature
            }
            VerifierErrorReason::HolderBindingAudienceMismatch
            | VerifierErrorReason::HolderBindingExpired
            | VerifierErrorReason::HolderBindingNonceMismatch
            | VerifierErrorReason::MissingHolderBindingClaim => {
                reallyme_openid4vp_types::ProblemKind::InvalidRequest
            }
        };
        Self::from_kind(kind)
    }
}

#[cfg(test)]
#[path = "jar_tests.rs"]
mod tests;
