// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use reallyme_openid4vp_types::AuthorizationResponse;
use serde::{Deserialize, Serialize};

use crate::{DcApiError, DcApiErrorReason};

/// Digital Credentials API response payload for `response_mode=dc_api`.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DcApiAuthorizationResponse {
    /// OpenID4VP Authorization Response data.
    pub data: AuthorizationResponse,
}

impl fmt::Debug for DcApiAuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DcApiAuthorizationResponse")
            .field("data", &"<redacted>")
            .finish()
    }
}

/// Digital Credentials API response payload for `response_mode=dc_api.jwt`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDcApiAuthorizationResponse {
    /// Encrypted JARM/JWE response string.
    pub response: String,
}

impl fmt::Debug for EncryptedDcApiAuthorizationResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedDcApiAuthorizationResponse")
            .field("byte_len", &self.response.len())
            .field("response", &"<redacted>")
            .finish()
    }
}

impl EncryptedDcApiAuthorizationResponse {
    /// Construct an encrypted DC API response wrapper.
    pub fn new(response: String) -> Result<Self, DcApiError> {
        if response.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::EmptyValue));
        }
        Ok(Self { response })
    }
}

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;
