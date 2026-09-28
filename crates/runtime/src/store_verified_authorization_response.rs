// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_codec::base64url::bytes_to_base64url;
use reallyme_crypto::{
    core::RngOutputKind,
    csprng::{generate_bytes, OsSecureRandom, SecureRandom},
};
use reallyme_openid4vp_verifier::{SessionRecord, VerifiedPresentation};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RuntimeError, RuntimeErrorReason};

/// Minimum encoded length for a response code carrying at least 128 random bits.
pub const MIN_RESPONSE_CODE_CHARS: usize = 22;
/// Defensive maximum for a response code returned by a host store.
pub const MAX_RESPONSE_CODE_CHARS: usize = 512;
const RESPONSE_CODE_RANDOM_BYTES: usize = 32;

/// Single-use opaque code that a host can redeem for a verified result.
#[derive(PartialEq, Eq)]
pub struct ResponseCode {
    value: String,
}

impl ResponseCode {
    /// Generate an opaque response code from the operating system CSPRNG.
    pub(crate) fn generate() -> Result<Self, RuntimeError> {
        Self::generate_with_rng(&mut OsSecureRandom)
    }

    fn generate_with_rng(rng: &mut impl SecureRandom) -> Result<Self, RuntimeError> {
        let random = generate_bytes::<RESPONSE_CODE_RANDOM_BYTES>(rng, RngOutputKind::Generic)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidResponseCode))?;
        Self::parse(bytes_to_base64url(random.as_bytes()))
    }

    /// Validate an externally returned response-code value.
    pub fn parse(value: String) -> Result<Self, RuntimeError> {
        if value.len() < MIN_RESPONSE_CODE_CHARS
            || value.len() > MAX_RESPONSE_CODE_CHARS
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseCode));
        }
        Ok(Self { value })
    }

    /// Borrow the validated wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseCode(<redacted>)")
    }
}

impl Zeroize for ResponseCode {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for ResponseCode {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ResponseCode {}

/// Borrowed result that can only be created after protocol validation succeeds.
///
/// Passing the typed domain response prevents host adapters from reparsing the
/// untrusted HTTP body and accidentally consuming presentations that were not
/// part of the verifier's accepted result.
pub struct VerifiedAuthorizationResponse<'a> {
    session: &'a SessionRecord,
    result: VerifiedAuthorizationResult,
}

impl<'a> VerifiedAuthorizationResponse<'a> {
    pub(crate) const fn new(
        session: &'a SessionRecord,
        result: VerifiedAuthorizationResult,
    ) -> Self {
        Self { session, result }
    }

    /// Borrow the server-owned session that authorized this result.
    #[must_use]
    pub const fn session(&self) -> &SessionRecord {
        self.session
    }

    /// Borrow the immutable result produced by protocol validation.
    #[must_use]
    pub const fn result(&self) -> &VerifiedAuthorizationResult {
        &self.result
    }

    /// Transfer the immutable result into durable adapter storage.
    #[must_use]
    pub fn into_result(mut self) -> VerifiedAuthorizationResult {
        core::mem::take(&mut self.result)
    }
}

/// Durable authorization result containing only cryptographically verified data.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct VerifiedAuthorizationResult {
    inbound_body_sha256: [u8; 32],
    presentations: Vec<VerifiedPresentation>,
}

impl VerifiedAuthorizationResult {
    pub(crate) fn new(raw_inbound_body: &[u8], presentations: Vec<VerifiedPresentation>) -> Self {
        Self {
            inbound_body_sha256: Sha256::digest(raw_inbound_body).into(),
            presentations,
        }
    }

    /// Hash of the exact HTTP body whose decoded response was accepted.
    #[must_use]
    pub const fn inbound_body_sha256(&self) -> &[u8; 32] {
        &self.inbound_body_sha256
    }

    /// Borrow verified disclosure and trust results without reparsing input.
    #[must_use]
    pub fn presentations(&self) -> &[VerifiedPresentation] {
        &self.presentations
    }
}

impl fmt::Debug for VerifiedAuthorizationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthorizationResult")
            .field("presentation_count", &self.presentations.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedAuthorizationResult {
    fn zeroize(&mut self) {
        self.inbound_body_sha256.zeroize();
        self.presentations.zeroize();
    }
}

impl Drop for VerifiedAuthorizationResult {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedAuthorizationResult {}

impl fmt::Debug for VerifiedAuthorizationResponse<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthorizationResponse")
            .field("session", &"<redacted>")
            .field("result", &self.result)
            .finish()
    }
}

#[cfg(test)]
#[path = "store_verified_authorization_response_tests.rs"]
mod tests;
