// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Atomic trust material for SD-JWT VC verification.

use core::fmt;

use reallyme_crypto::jwk::Jwk;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{SdJwtFormatError, SdJwtFormatErrorReason};

const MAX_ISSUER_IDENTIFIER_BYTES: usize = 8 * 1024;

/// Issuer identity authenticated by deployment trust policy.
///
/// This value is intentionally opaque: callers may create it only after
/// resolving issuer metadata or validating an X.509 path, and the format
/// verifier consumes it to bind the signed `iss` claim to that decision.
pub struct SdJwtIssuerIdentity(Zeroizing<String>);

impl SdJwtIssuerIdentity {
    /// Build authenticated issuer-identity evidence from a canonical identifier.
    pub fn new(value: String) -> Result<Self, SdJwtFormatError> {
        if value.is_empty() || value.len() > MAX_ISSUER_IDENTIFIER_BYTES {
            return Err(SdJwtFormatError::new(
                SdJwtFormatErrorReason::KeyResolutionFailed,
            ));
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub(super) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SdJwtIssuerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SdJwtIssuerIdentity(<redacted>)")
    }
}

/// Public verification keys and authenticated issuer identity resolved under
/// one atomic deployment trust decision.
pub struct SdJwtVerificationKeyMaterial {
    /// Issuer verification JWK.
    pub issuer_jwk: Jwk,
    /// Canonical issuer public-key bytes matching `issuer_jwk`.
    pub issuer_public_key: Vec<u8>,
    /// Holder JWK expected to match the issuer-signed `cnf.jwk`.
    pub holder_jwk: Jwk,
    /// Canonical holder public-key bytes matching `holder_jwk`.
    pub holder_public_key: Vec<u8>,
    /// Provenance of the trusted issuer verification key.
    pub issuer_key_source: SdJwtIssuerKeySource,
    /// Canonical identity authenticated by the same trust decision as the key.
    pub(super) issuer_identity: SdJwtIssuerIdentity,
}

impl SdJwtVerificationKeyMaterial {
    /// Build one atomic issuer-key, holder-key, and issuer-identity decision.
    pub fn new(
        issuer_jwk: Jwk,
        issuer_public_key: Vec<u8>,
        holder_jwk: Jwk,
        holder_public_key: Vec<u8>,
        issuer_key_source: SdJwtIssuerKeySource,
        issuer_identity: SdJwtIssuerIdentity,
    ) -> Self {
        Self {
            issuer_jwk,
            issuer_public_key,
            holder_jwk,
            holder_public_key,
            issuer_key_source,
            issuer_identity,
        }
    }
}

/// Trust-provider proof for how the issuer verification key was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdJwtIssuerKeySource {
    /// Key was resolved through deployment trust policy and the issuer JWT must
    /// not carry embedded key material.
    Resolved,
    /// Key was extracted from and bound to the exact authenticated leaf of the
    /// issuer JWT's `x5c` path after full deployment trust validation.
    AuthenticatedX509Header,
}

impl fmt::Debug for SdJwtVerificationKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdJwtVerificationKeyMaterial")
            .field("issuer_public_key_len", &self.issuer_public_key.len())
            .field("holder_public_key_len", &self.holder_public_key.len())
            .field("issuer_key_source", &self.issuer_key_source)
            .field("issuer_identity", &"<redacted>")
            .field("key_material", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SdJwtVerificationKeyMaterial {
    fn zeroize(&mut self) {
        self.issuer_public_key.zeroize();
        self.holder_public_key.zeroize();
    }
}

impl Drop for SdJwtVerificationKeyMaterial {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SdJwtVerificationKeyMaterial {}
