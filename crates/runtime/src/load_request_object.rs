// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_verifier::CompactJwt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RuntimeError, RuntimeErrorReason};

/// Hosted Request Object material loaded by the runtime host.
///
/// GET retrievals store an already-signed JWT. POST retrievals store the
/// unsigned request because the wallet nonce does not exist until the wallet
/// calls `request_uri`; the runtime binds that nonce before signing.
#[derive(Clone, PartialEq)]
pub enum HostedRequestObject {
    /// Request Object signed during launch for `request_uri_method=get`.
    Signed {
        /// Compact signed Request Object JWT.
        request_object_jwt: CompactJwt,
    },
    /// Request Object awaiting a wallet-provided nonce for
    /// `request_uri_method=post`.
    DeferredPost {
        /// Validated request template that will be cloned, nonce-bound, and
        /// signed only after a valid POST is received.
        authorization_request: Box<AuthorizationRequestObject>,
    },
}

impl fmt::Debug for HostedRequestObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, byte_len) = match self {
            Self::Signed { request_object_jwt } => {
                ("Signed", Some(request_object_jwt.as_str().len()))
            }
            Self::DeferredPost { .. } => ("DeferredPost", None),
        };
        formatter
            .debug_struct("HostedRequestObject")
            .field("kind", &kind)
            .field("request_object_jwt_byte_len", &byte_len)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for HostedRequestObject {
    fn zeroize(&mut self) {
        match self {
            Self::Signed { request_object_jwt } => request_object_jwt.zeroize(),
            Self::DeferredPost {
                authorization_request,
            } => authorization_request.zeroize(),
        }
    }
}

impl Drop for HostedRequestObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HostedRequestObject {}

impl HostedRequestObject {
    /// Construct an already-signed GET Request Object.
    pub fn signed(request_object_jwt: CompactJwt) -> Self {
        Self::Signed { request_object_jwt }
    }

    /// Construct a POST Request Object template whose wallet nonce will be
    /// bound immediately before signing.
    pub fn deferred_post(
        authorization_request: AuthorizationRequestObject,
    ) -> Result<Self, RuntimeError> {
        if authorization_request.wallet_nonce.is_some() {
            return Err(RuntimeError::new(RuntimeErrorReason::WalletNonceMismatch));
        }
        Ok(Self::DeferredPost {
            authorization_request: Box::new(authorization_request),
        })
    }
}

/// Storage boundary for hosted Request Objects.
pub trait RequestObjectStore: Send + Sync {
    /// Load hosted Request Object material by an adapter-defined lookup key.
    fn load_request_object(&self, key: &str) -> Result<HostedRequestObject, RuntimeError>;
}

#[cfg(test)]
#[path = "load_request_object_tests.rs"]
mod tests;
