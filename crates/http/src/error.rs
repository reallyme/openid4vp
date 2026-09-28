// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// HTTP adapter error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP HTTP adapter error: {reason:?}")]
pub struct HttpAdapterError {
    reason: HttpAdapterErrorReason,
}

impl HttpAdapterError {
    /// Build an HTTP adapter error from a stable reason.
    pub const fn new(reason: HttpAdapterErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> HttpAdapterErrorReason {
        self.reason
    }
}

/// Stable HTTP adapter error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAdapterErrorReason {
    /// A non-HTTPS `request_uri` was rejected by policy.
    RequestUriMustBeHttps,
    /// A `request_uri` authority targets an unsafe local or metadata endpoint.
    UnsafeRequestUri,
    /// Fetching the Request Object failed.
    RequestUriFetchFailed,
    /// The Request Object endpoint returned a non-success status.
    InvalidRequestObjectHttpStatus,
    /// The Request Object endpoint returned a missing or invalid media type.
    InvalidRequestObjectMediaType,
    /// Fetched Request Object bytes were not UTF-8.
    InvalidRequestObjectEncoding,
    /// Fetched Request Object exceeded policy.
    RequestObjectTooLarge,
    /// Request transport did not contain a `request_uri`.
    RequestUriRequired,
    /// An explicitly supplied POST `wallet_nonce` was empty.
    MissingWalletNonce,
}
