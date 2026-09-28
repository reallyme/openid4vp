// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientMetadata};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WalletError, WalletErrorReason};

/// Fresh, trusted verifier metadata resolved outside the pure wallet parser.
///
/// OpenID4VP 1.0 final carries verifier metadata inline in `client_metadata`.
/// Some deployments experiment with metadata-by-reference. This evidence type
/// lets ReallyMe Identity or a service host inject a cache/trust decision without
/// teaching wallet request parsing to fetch network resources.
#[derive(Clone, PartialEq)]
pub struct VerifiedClientMetadataReference {
    /// Exact metadata URI from the Request Object extension.
    pub uri: String,
    /// Metadata JSON obtained after host trust policy and cache validation.
    pub metadata: ClientMetadata,
    /// Absolute Unix timestamp after which this evidence is stale.
    pub expires_at_unix: u64,
}

impl fmt::Debug for VerifiedClientMetadataReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedClientMetadataReference")
            .field("expires_at_unix", &self.expires_at_unix)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedClientMetadataReference {
    fn zeroize(&mut self) {
        self.uri.zeroize();
        self.metadata.zeroize();
        self.expires_at_unix.zeroize();
    }
}

impl Drop for VerifiedClientMetadataReference {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedClientMetadataReference {}

impl VerifiedClientMetadataReference {
    /// Build verified metadata-reference evidence after structural checks.
    pub fn new(
        uri: String,
        metadata: ClientMetadata,
        expires_at_unix: u64,
    ) -> Result<Self, WalletError> {
        if uri.is_empty() || expires_at_unix == 0 {
            return Err(WalletError::new(
                WalletErrorReason::InvalidMetadataReference,
            ));
        }
        Ok(Self {
            uri,
            metadata,
            expires_at_unix,
        })
    }
}

/// Validate metadata-by-reference evidence against a Request Object.
pub fn validate_client_metadata_reference_binding(
    request: &AuthorizationRequestObject,
    evidence: Option<&VerifiedClientMetadataReference>,
    now_unix: u64,
) -> Result<(), WalletError> {
    let Some(uri) = request.client_metadata_uri.as_deref() else {
        return Ok(());
    };

    if request.client_metadata.is_some() {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    }

    let Some(reference) = evidence else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    };
    if reference.uri != uri || reference.expires_at_unix <= now_unix {
        return Err(WalletError::new(
            WalletErrorReason::InvalidMetadataReference,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "metadata_reference_tests.rs"]
mod tests;
