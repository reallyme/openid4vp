// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Machine-readable OpenID4VP conformance vector types.

use serde::{Deserialize, Serialize};

/// Expected result for a vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedResult {
    /// Vector must be accepted.
    Accept,
    /// Vector must be rejected.
    Reject,
}

/// One conformance vector case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceVector {
    /// Stable vector identifier.
    pub id: String,
    /// Spec section or local security policy covered by the vector.
    pub spec_section: String,
    /// Target module or endpoint.
    pub target: String,
    /// Input payload. For JSON targets this is strict JSON; for transport
    /// targets it is an authorization request URI or query string.
    pub input: String,
    /// Expected result.
    pub expected: ExpectedResult,
}
