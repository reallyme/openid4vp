// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Error returned by OpenID4VP protocol type helpers.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid OpenID4VP type: {reason:?}")]
pub struct OpenId4vpTypeError {
    reason: OpenId4vpTypeErrorReason,
}

impl OpenId4vpTypeError {
    /// Build a typed error from a stable reason.
    pub const fn new(reason: OpenId4vpTypeErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> OpenId4vpTypeErrorReason {
        self.reason
    }
}

/// Stable OpenID4VP type error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenId4vpTypeErrorReason {
    /// A required value was empty.
    EmptyValue,
    /// A required collection was empty.
    EmptyCollection,
    /// The client identifier prefix is reserved or invalid for this context.
    InvalidClientIdentifierPrefix,
    /// No mutually supported metadata capability exists.
    UnsupportedMetadataCapability,
    /// The transaction data hash algorithm is unsupported.
    UnsupportedTransactionDataHashAlgorithm,
    /// A compact JWT had an invalid Request Object shape.
    InvalidRequestObjectJwt,
    /// Deterministic JSON serialization failed.
    SerializationFailed,
    /// A base64url-encoded protocol value was malformed.
    InvalidEncoding,
    /// JSON input exceeded this crate's own canonicalization recursion limit.
    JsonDepthExceeded,
    /// JSON input exceeded the transaction-data boundary limit.
    JsonSizeExceeded,
    /// JSON input contained a duplicate object property.
    DuplicateJsonKey,
    /// Response construction received an empty presentation list.
    EmptyPresentationList,
}
