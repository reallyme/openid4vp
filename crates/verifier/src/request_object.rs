// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::AuthorizationRequestObject;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::VerifierError;

/// Verified Request Object and its parsed claims.
#[derive(Clone, PartialEq)]
pub struct VerifiedRequestObject {
    /// Parsed Authorization Request Object.
    pub request: AuthorizationRequestObject,
}

impl fmt::Debug for VerifiedRequestObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedRequestObject(<redacted>)")
    }
}

impl Zeroize for VerifiedRequestObject {
    fn zeroize(&mut self) {
        self.request.zeroize();
    }
}

impl Drop for VerifiedRequestObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedRequestObject {}

/// Network-free Request Object verifier.
///
/// Implementations resolve keys from already-injected trust material or from
/// caller-provided adapters. Fetching `request_uri`, DID documents, federation
/// chains, or X.509 trust lists belongs outside this trait.
pub trait RequestObjectVerifier: Send + Sync {
    /// Verify a compact Request Object JWT and return parsed claims.
    fn verify_and_parse(
        &self,
        jwt: &str,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, VerifierError>;
}
