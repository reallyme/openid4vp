// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! SDK-facing OpenID4VP request-processing policy.
//!
//! This conversion facade deliberately covers only Authorization Request
//! transport bounds, Request Object claim validation, and `request_uri`
//! response bounds. Trust anchors, Client Identifier Prefix capabilities,
//! transaction semantics, JOSE algorithms, and runtime endpoint limits remain
//! explicit policies at their owning security boundaries. Keeping those
//! policies separate prevents this type from promising enforcement it cannot
//! provide.

use reallyme_openid4vp_verifier::JarPolicy;
use reallyme_openid4vp_wallet::RequestTransportPolicy;

/// Maximum compact Request Object JWT bytes accepted by default.
pub const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
/// Maximum authorization request URI/query bytes accepted by default.
pub const DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum authorization request parameter count accepted by default.
pub const DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS: usize = 64;

/// Maximum Request Object lifetime accepted by default, in seconds.
pub const DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS: u64 = 300;

/// Accepted future clock skew for Request Object `iat`, in seconds.
pub const DEFAULT_ISSUED_AT_FUTURE_SKEW_SECS: u64 = 60;

/// Shared policy for the Authorization Request processing stages listed above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenId4VpRequestPolicy {
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Maximum accepted front-channel Authorization Request size in bytes.
    pub max_authorization_request_bytes: usize,
    /// Maximum accepted front-channel Authorization Request parameter count.
    pub max_authorization_request_parameters: usize,
    /// Reject inline Authorization Request parameters unless a signed Request
    /// Object is present. Production wallets should leave this enabled because
    /// final OpenID4VP deployments bind verifier identity through signed JAR.
    pub require_signed_request_object: bool,
    /// Require an issuer claim in Request Objects.
    pub require_request_object_issuer: bool,
    /// Require issuer to equal the final-prefixed client identifier.
    pub require_issuer_matches_client_id: bool,
    /// Require an audience claim in Request Objects.
    pub require_request_object_audience: bool,
    /// Require an issued-at claim in Request Objects.
    pub require_request_object_issued_at: bool,
    /// Require an expiration claim in Request Objects.
    pub require_request_object_expiration: bool,
    /// Maximum accepted Request Object lifetime, in seconds.
    pub max_request_object_lifetime_secs: Option<u64>,
    /// Accepted clock skew for issued-at values in the future.
    pub issued_at_future_skew_secs: u64,
}

impl OpenId4VpRequestPolicy {
    /// Return a strict production policy suitable for ReallyMe Identity defaults.
    pub const fn production() -> Self {
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            max_authorization_request_bytes: DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES,
            max_authorization_request_parameters: DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS,
            require_signed_request_object: true,
            require_request_object_issuer: true,
            require_issuer_matches_client_id: true,
            require_request_object_audience: true,
            require_request_object_issued_at: true,
            require_request_object_expiration: true,
            max_request_object_lifetime_secs: Some(DEFAULT_MAX_REQUEST_OBJECT_LIFETIME_SECS),
            issued_at_future_skew_secs: DEFAULT_ISSUED_AT_FUTURE_SKEW_SECS,
        }
    }

    /// Convert to the wallet transport parser policy.
    pub const fn wallet_transport_policy(self) -> RequestTransportPolicy {
        RequestTransportPolicy {
            max_request_jwt_bytes: self.max_request_jwt_bytes,
            max_authorization_request_bytes: self.max_authorization_request_bytes,
            max_authorization_request_parameters: self.max_authorization_request_parameters,
            require_signed_request_object: self.require_signed_request_object,
        }
    }

    /// Convert to the verifier Request Object claim policy.
    pub const fn jar_policy(self) -> JarPolicy {
        JarPolicy {
            require_issuer: self.require_request_object_issuer,
            require_issuer_matches_client_id: self.require_issuer_matches_client_id,
            require_audience: self.require_request_object_audience,
            require_issued_at: self.require_request_object_issued_at,
            require_expiration: self.require_request_object_expiration,
            max_lifetime_secs: self.max_request_object_lifetime_secs,
            issued_at_future_skew_secs: self.issued_at_future_skew_secs,
        }
    }

    /// Convert to the HTTP `request_uri` resolution policy.
    #[cfg(feature = "http")]
    pub const fn request_uri_resolution_policy(
        self,
    ) -> reallyme_openid4vp_http::RequestUriResolutionPolicy {
        reallyme_openid4vp_http::RequestUriResolutionPolicy {
            max_request_jwt_bytes: self.max_request_jwt_bytes,
            post_wallet_nonce: None,
            network_policy: reallyme_openid4vp_http::RequestUriNetworkPolicy::PublicOnly,
        }
    }
}

impl Default for OpenId4VpRequestPolicy {
    fn default() -> Self {
        Self::production()
    }
}

impl From<OpenId4VpRequestPolicy> for RequestTransportPolicy {
    fn from(policy: OpenId4VpRequestPolicy) -> Self {
        policy.wallet_transport_policy()
    }
}

impl From<OpenId4VpRequestPolicy> for JarPolicy {
    fn from(policy: OpenId4VpRequestPolicy) -> Self {
        policy.jar_policy()
    }
}

#[cfg(feature = "http")]
impl From<OpenId4VpRequestPolicy> for reallyme_openid4vp_http::RequestUriResolutionPolicy {
    fn from(policy: OpenId4VpRequestPolicy) -> Self {
        policy.request_uri_resolution_policy()
    }
}

#[cfg(test)]
#[path = "configure_policy_tests.rs"]
mod tests;
