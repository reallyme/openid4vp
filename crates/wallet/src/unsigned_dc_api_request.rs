// SPDX-FileCopyrightText: 2026 ReallyMe LLC
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
    Ok(VerifiedUnsignedDcApiRequest {
        request: request.clone(),
    })
}

#[cfg(test)]
#[path = "unsigned_dc_api_request_tests.rs"]
mod tests;
