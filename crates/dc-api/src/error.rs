// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Digital Credentials API binding error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP Digital Credentials API error: {reason:?}")]
pub struct DcApiError {
    reason: DcApiErrorReason,
}

impl DcApiError {
    /// Build an error from a stable reason.
    pub const fn new(reason: DcApiErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> DcApiErrorReason {
        self.reason
    }
}

/// Stable Digital Credentials API binding error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DcApiErrorReason {
    /// A required input was empty.
    EmptyValue,
    /// The DC API request set was empty.
    EmptyRequestSet,
    /// The protocol identifier is unsupported or malformed.
    InvalidProtocol,
    /// A signed or multi-signed Request Object has an invalid wire shape.
    InvalidRequestObject,
    /// A signed or multi-signed Request Object exceeds its input budget.
    RequestObjectTooLarge,
    /// A multi-signed Request Object exceeds its signature-count budget.
    TooManyRequestObjectSignatures,
    /// Handover CBOR encoding failed in the delegated mdoc adapter.
    HandoverEncodingFailed,
    /// A handover text value exceeds its bounded input budget.
    HandoverValueTooLarge,
}
