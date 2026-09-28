// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stable OpenID4VP error mapping for the SSI SD-JWT verifier boundary.

use reallyme_sd_jwt::SdJwtEnvelopeError;

use crate::sd_jwt::{SdJwtFormatError, SdJwtFormatErrorReason};

pub(super) fn map_sd_jwt_envelope_error(error: SdJwtEnvelopeError) -> SdJwtFormatError {
    let reason = match error {
        SdJwtEnvelopeError::InvalidIssuerJwt => SdJwtFormatErrorReason::InvalidCredentialSignature,
        SdJwtEnvelopeError::InvalidKeyBindingJwt => SdJwtFormatErrorReason::InvalidHolderBinding,
        SdJwtEnvelopeError::InvalidTemporalClaim
        | SdJwtEnvelopeError::CredentialExpired
        | SdJwtEnvelopeError::CredentialNotYetValid => {
            SdJwtFormatErrorReason::InvalidCredentialValidity
        }
        SdJwtEnvelopeError::CredentialStatusNotVerified => {
            SdJwtFormatErrorReason::InvalidCredentialStatus
        }
        // The upstream enum is non-exhaustive. Unknown structural and policy
        // failures remain a closed, non-sensitive presentation rejection.
        _ => SdJwtFormatErrorReason::InvalidPresentation,
    };
    SdJwtFormatError::new(reason)
}
