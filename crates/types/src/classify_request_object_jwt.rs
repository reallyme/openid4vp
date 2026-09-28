// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};
use reallyme_codec::base64url::base64url_to_bytes;

const COMPACT_JWS_SEGMENT_COUNT: usize = 3;
const COMPACT_JWE_SEGMENT_COUNT: usize = 5;
const JWE_ENCRYPTED_KEY_SEGMENT_INDEX: usize = 1;

/// RFC 9101 compact Request Object serialization kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestObjectJwtKind {
    /// JWS-signed Request Object passed by value or fetched by reference.
    Signed,
    /// JWE-encrypted Request Object. For nested JWTs, the decrypted payload is
    /// expected to be a signed Request Object verified by the injected JOSE layer.
    Encrypted,
}

/// Classify a compact RFC 9101 Request Object JWT before JOSE processing.
///
/// This is intentionally structural only: signature verification, decryption,
/// algorithm policy, `kid` binding, and nested signed-then-encrypted validation
/// belong to the injected JOSE verifier. The pure protocol layers still reject
/// malformed segment counts and non-base64url bytes early so malformed transport
/// data does not reach cryptographic adapters.
pub fn classify_request_object_jwt(jwt: &str) -> Result<RequestObjectJwtKind, OpenId4vpTypeError> {
    if jwt.is_empty() || jwt.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(invalid_request_object_jwt());
    }

    let mut segment_count = 0usize;
    for (index, segment) in jwt.split('.').enumerate() {
        if index >= COMPACT_JWE_SEGMENT_COUNT {
            return Err(invalid_request_object_jwt());
        }
        if segment.is_empty() && index != JWE_ENCRYPTED_KEY_SEGMENT_INDEX {
            return Err(invalid_request_object_jwt());
        }
        validate_base64url_segment(segment)?;
        segment_count = segment_count
            .checked_add(1)
            .ok_or_else(invalid_request_object_jwt)?;
    }

    match segment_count {
        COMPACT_JWS_SEGMENT_COUNT => Ok(RequestObjectJwtKind::Signed),
        COMPACT_JWE_SEGMENT_COUNT => Ok(RequestObjectJwtKind::Encrypted),
        _ => Err(invalid_request_object_jwt()),
    }
}

const fn invalid_request_object_jwt() -> OpenId4vpTypeError {
    OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidRequestObjectJwt)
}

fn validate_base64url_segment(segment: &str) -> Result<(), OpenId4vpTypeError> {
    base64url_to_bytes(segment).map_err(|_| invalid_request_object_jwt())?;
    Ok(())
}

#[cfg(test)]
#[path = "classify_request_object_jwt_tests.rs"]
mod tests;
