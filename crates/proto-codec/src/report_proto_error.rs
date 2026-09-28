// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::OpenId4vpTypeError;
use thiserror::Error;

/// OpenID4VP protobuf codec error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenId4VpProtoError {
    /// Protobuf bytes could not be decoded.
    #[error("invalid OpenID4VP protobuf")]
    Decode,
    /// Protobuf bytes could not be encoded.
    #[error("invalid OpenID4VP protobuf encoding")]
    Encode,
    /// A required protobuf field was absent.
    #[error("required OpenID4VP protobuf field missing")]
    MissingField,
    /// A protobuf enum value is not supported by the Rust model.
    #[error("invalid OpenID4VP protobuf enum value")]
    InvalidEnumValue,
    /// A protobuf field failed Rust domain validation.
    #[error("invalid OpenID4VP protobuf field")]
    InvalidField,
    /// Generated protobuf JSON serialization failed.
    #[error("invalid OpenID4VP protobuf JSON serialization")]
    JsonSerialize,
    /// Generated protobuf JSON deserialization failed.
    #[error("invalid OpenID4VP protobuf JSON")]
    JsonDeserialize,
    /// JSON embedded in a protobuf field exceeded its field-specific byte limit.
    #[error("OpenID4VP protobuf JSON exceeds policy")]
    JsonTooLarge,
    /// JSON embedded in a protobuf field exceeded the nesting limit.
    #[error("OpenID4VP protobuf JSON nesting exceeds policy")]
    JsonNestingTooDeep,
    /// JSON embedded in a protobuf field contained a duplicate object key.
    #[error("OpenID4VP protobuf JSON contains a duplicate object key")]
    JsonDuplicateKey,
}

impl From<OpenId4vpTypeError> for OpenId4VpProtoError {
    fn from(_value: OpenId4vpTypeError) -> Self {
        Self::InvalidField
    }
}
