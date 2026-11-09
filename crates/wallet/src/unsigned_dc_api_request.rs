// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_dcql::validate_query;
use reallyme_openid4vp_types::{AuthorizationRequestObject, ResponseMode};

use crate::jar::{sealed, WalletAuthorizationRequest};
use crate::{WalletError, WalletErrorReason, WalletTransactionDataPolicy};

/// Opaque receipt for an unsigned request delivered by the browser Digital
/// Credentials API security boundary.
///
/// This is intentionally distinct from [`crate::VerifiedWalletRequest`]: an
/// unsigned request is authorized by the invoking origin rather than a Request
/// Object signature.
#[derive(Clone, PartialEq)]
pub struct VerifiedUnsignedDcApiRequest {
    request: AuthorizationRequestObject,
    untrusted_time_hint: Option<UnsignedDcApiTimeHint>,
}

/// Unauthenticated timing parameters supplied by an unsigned DC API requester.
///
/// These values may be used only as a proposed ZK transcript time. They do not
/// establish requester identity, freshness, or authorization. The verifier must
/// compare the proof time to its independently retained session binding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnsignedDcApiTimeHint {
    issued_at_unix: u64,
    expires_at_unix: u64,
}

impl UnsignedDcApiTimeHint {
    /// Proposed verifier session issuance time, without wallet-side authenticity.
    #[must_use]
    pub const fn issued_at_unix(self) -> u64 {
        self.issued_at_unix
    }

    /// Proposed verifier session expiry, without wallet-side authenticity.
    #[must_use]
    pub const fn expires_at_unix(self) -> u64 {
        self.expires_at_unix
    }
}

impl VerifiedUnsignedDcApiRequest {
    /// Return the unsigned request's optional transcript hint separately from
    /// authenticated request claims. An incomplete pair is never usable.
    #[must_use]
    pub const fn untrusted_time_hint(&self) -> Option<UnsignedDcApiTimeHint> {
        self.untrusted_time_hint
    }
}

impl sealed::SealedWalletRequest for VerifiedUnsignedDcApiRequest {
    fn authorization_request(&self) -> &AuthorizationRequestObject {
        &self.request
    }
}

impl WalletAuthorizationRequest for VerifiedUnsignedDcApiRequest {}

impl core::fmt::Debug for VerifiedUnsignedDcApiRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("VerifiedUnsignedDcApiRequest(<redacted>)")
    }
}

impl zeroize::Zeroize for VerifiedUnsignedDcApiRequest {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.request);
        self.untrusted_time_hint = None;
    }
}

impl Drop for VerifiedUnsignedDcApiRequest {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for VerifiedUnsignedDcApiRequest {}

/// Validate an unsigned Digital Credentials API request with fail-closed defaults.
///
/// The browser supplies verifier identity through its invoking-origin security
/// boundary. OpenID4VP Appendix A.2 consequently requires `client_id` and
/// `expected_origins` request members to be ignored on this path.
pub fn validate_unsigned_dc_api_request(
    request: &AuthorizationRequestObject,
) -> Result<VerifiedUnsignedDcApiRequest, WalletError> {
    validate_unsigned_dc_api_request_with_transaction_data_policy(
        request,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Validate an unsigned DC API request with supported transaction-data types.
pub fn validate_unsigned_dc_api_request_with_transaction_data_policy(
    request: &AuthorizationRequestObject,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<VerifiedUnsignedDcApiRequest, WalletError> {
    if !matches!(
        request.response_mode,
        Some(ResponseMode::DcApi | ResponseMode::DcApiJwt)
    ) || request.response_uri.is_some()
        || request.redirect_uri.is_some()
        || request.wallet_nonce.is_some()
        || request.nonce.is_empty()
        || reallyme_openid4vp_types::validate_oauth_binding_value(&request.nonce).is_err()
    {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }

    validate_query(&request.dcql_query)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidAuthorizationRequestTransport))?;

    if request.client_metadata_uri.is_some() {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    }

    transaction_data_policy.validate(request)?;
    let untrusted_time_hint =
        request
            .iat
            .zip(request.exp)
            .map(|(issued_at_unix, expires_at_unix)| UnsignedDcApiTimeHint {
                issued_at_unix,
                expires_at_unix,
            });
    let mut accepted = request.clone();
    // These fields have no authenticated requester binding in an unsigned DC
    // API request. Keeping them on the receipt would let downstream policy use
    // attacker-supplied identity or attestation material as verified input.
    accepted.client_id = None;
    accepted.expected_origins = None;
    accepted.verifier_info = None;
    accepted.iss = None;
    accepted.aud = None;
    accepted.iat = None;
    accepted.exp = None;
    accepted.state = None;
    Ok(VerifiedUnsignedDcApiRequest {
        request: accepted,
        untrusted_time_hint,
    })
}

#[cfg(test)]
#[path = "unsigned_dc_api_request_tests.rs"]
mod tests;
