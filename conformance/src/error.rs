// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance harness errors.

use thiserror::Error;

/// Result alias for conformance vector loading and execution.
pub type ConformanceResult<T> = Result<T, ConformanceError>;

/// Conformance vector loading or execution error.
#[non_exhaustive]
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceError {
    /// The vector JSON was malformed.
    #[error("invalid_vector_json")]
    InvalidJson,
    /// A vector named a `target` the runner does not know how to dispatch.
    #[error("unknown_target")]
    UnknownTarget,
    /// The strict JSON guard found a duplicate object member.
    #[error("duplicate_json_key")]
    DuplicateJsonKey,
    /// The strict JSON guard exceeded the configured nesting limit.
    #[error("json_nesting_limit_exceeded")]
    JsonNestingLimitExceeded,
}
