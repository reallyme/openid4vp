// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_dcql::CredentialFormat;
use reallyme_openid4vp_types::AuthorizationRequestObject;

use crate::{WalletError, WalletErrorReason};

/// Wallet allowlist for application-defined transaction-data types.
///
/// Transaction data changes what the holder authorizes. Unknown application
/// types therefore fail closed instead of being displayed or signed with
/// semantics the wallet does not understand.
#[derive(Clone, Copy)]
pub struct WalletTransactionDataPolicy<'a> {
    supported_types: &'a [&'a str],
}

impl<'a> WalletTransactionDataPolicy<'a> {
    /// Construct a policy that rejects every transaction-data type.
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            supported_types: &[],
        }
    }

    /// Construct a policy from exact, non-empty, unique type identifiers.
    pub fn new(supported_types: &'a [&'a str]) -> Result<Self, WalletError> {
        for (index, transaction_type) in supported_types.iter().enumerate() {
            if transaction_type.is_empty() || supported_types[..index].contains(transaction_type) {
                return Err(WalletError::new(WalletErrorReason::InvalidTransactionData));
            }
        }
        Ok(Self { supported_types })
    }

    pub(crate) fn validate(self, request: &AuthorizationRequestObject) -> Result<(), WalletError> {
        let Some(transaction_data) = request.transaction_data.as_ref() else {
            return Ok(());
        };
        if transaction_data.is_empty() {
            return Err(WalletError::new(WalletErrorReason::InvalidTransactionData));
        }
        if transaction_data
            .iter()
            .any(|value| !self.supported_types.contains(&value.transaction_type()))
        {
            return Err(WalletError::new(WalletErrorReason::InvalidTransactionData));
        }
        for transaction in transaction_data {
            for credential_id in transaction.credential_ids() {
                let query = request
                    .dcql_query
                    .credentials
                    .iter()
                    .find(|query| query.id.as_str() == credential_id)
                    .ok_or_else(|| WalletError::new(WalletErrorReason::InvalidTransactionData))?;
                // Transaction authorization with SD-JWT requires the holder's
                // signature. An allowlisted application type cannot override
                // the format's mandatory cryptographic binding requirement.
                if query.format.as_str() == CredentialFormat::DC_SD_JWT
                    && !query.require_cryptographic_holder_binding
                {
                    return Err(WalletError::new(WalletErrorReason::InvalidTransactionData));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "transaction_data_policy_tests.rs"]
mod tests;

impl Default for WalletTransactionDataPolicy<'_> {
    fn default() -> Self {
        Self::deny_all()
    }
}

impl fmt::Debug for WalletTransactionDataPolicy<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletTransactionDataPolicy")
            .field("supported_type_count", &self.supported_types.len())
            .finish()
    }
}
