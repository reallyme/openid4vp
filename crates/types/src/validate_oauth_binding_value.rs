// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// Validate the ASCII URL-safe syntax required for nonce and state by
/// OpenID4VP 1.0 Section 5.2, without normalizing the opaque value.
///
/// Presence, minimum length, and random generation remain caller policy.
/// This check neither measures nor establishes cryptographic entropy.
pub fn validate_oauth_binding_value(value: &str) -> Result<(), OpenId4vpTypeError> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(OpenId4vpTypeError::new(
            OpenId4vpTypeErrorReason::InvalidEncoding,
        ));
    }
    Ok(())
}
