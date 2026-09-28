// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_formats::sd_jwt::{
    verify_sd_jwt_presentation, SdJwtFormatError, SdJwtFormatErrorReason,
    SdJwtPresentationVerificationInput, SdJwtTrustProvider,
};
use reallyme_openid4vp_types::PresentationValue;

use crate::{
    holder_binding::expected_holder_binding_audience, HolderBindingClaims,
    HolderBindingVerificationContext, HolderBindingVerifier, VerifiedDisclosureSet,
    VerifiedHolderBinding, VerifiedJsonClaims, VerifiedTrustProvenance, VerifierError,
    VerifierErrorReason,
};

/// Production SD-JWT VC adapter for verifier response validation.
///
/// Trust discovery and credential-status I/O remain deployment-owned, while
/// this adapter guarantees that issuer verification, RFC 9901 key binding,
/// the active OpenID4VP session, and the exact DCQL credential query are
/// evaluated as one operation before claims enter the verifier engine.
pub struct SdJwtHolderBindingVerifier<'a> {
    trust_provider: &'a dyn SdJwtTrustProvider,
}

impl<'a> SdJwtHolderBindingVerifier<'a> {
    /// Bind the format verifier to a deployment trust and status provider.
    #[must_use]
    pub const fn new(trust_provider: &'a dyn SdJwtTrustProvider) -> Self {
        Self { trust_provider }
    }
}

impl HolderBindingVerifier for SdJwtHolderBindingVerifier<'_> {
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        let PresentationValue::Compact(compact) = presentation else {
            return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
        };
        let expected_audience = expected_holder_binding_audience(&context.session().binding);
        let mut verified = verify_sd_jwt_presentation(
            SdJwtPresentationVerificationInput {
                compact,
                expected_audience: &expected_audience,
                expected_nonce: &context.session().binding.nonce,
                now_unix: context.now_unix(),
                credential_query: context.credential_query(),
            },
            self.trust_provider,
        )
        .map_err(map_sd_jwt_error)?;

        let claims = HolderBindingClaims {
            audience: core::mem::take(&mut verified.audience),
            nonce: core::mem::take(&mut verified.nonce),
            expiration_unix: verified.expiration_unix,
            issued_at_unix: verified.issued_at_unix,
            sd_hash: Some(core::mem::take(&mut verified.sd_hash)),
            transaction_data_hashes: core::mem::take(&mut verified.transaction_data_hashes),
            transaction_data_hashes_alg: verified.transaction_data_hashes_alg.take(),
        };
        let resolved_payload = VerifiedJsonClaims::from_authenticated(core::mem::take(
            &mut verified.resolved_payload,
        ))?;
        let provenance = match verified.issuer_key_source {
            reallyme_openid4vp_formats::sd_jwt::SdJwtIssuerKeySource::Resolved => {
                VerifiedTrustProvenance::ResolvedIssuerKey
            }
            reallyme_openid4vp_formats::sd_jwt::SdJwtIssuerKeySource::AuthenticatedX509Header => {
                VerifiedTrustProvenance::AuthenticatedX509
            }
        };
        Ok(VerifiedHolderBinding::new(
            claims,
            VerifiedDisclosureSet::SdJwt(resolved_payload),
            provenance,
        ))
    }
}

fn map_sd_jwt_error(error: SdJwtFormatError) -> VerifierError {
    let reason = match error.reason() {
        SdJwtFormatErrorReason::MissingHolderBindingClaim => {
            VerifierErrorReason::MissingHolderBindingClaim
        }
        SdJwtFormatErrorReason::CredentialRevoked => VerifierErrorReason::CredentialRevoked,
        SdJwtFormatErrorReason::InvalidCredentialStatus => {
            VerifierErrorReason::InvalidCredentialStatus
        }
        SdJwtFormatErrorReason::CredentialStatusUnavailable => {
            VerifierErrorReason::CredentialStatusUnavailable
        }
        SdJwtFormatErrorReason::InvalidCredentialValidity => {
            VerifierErrorReason::InvalidCredentialValidity
        }
        SdJwtFormatErrorReason::CredentialQueryMismatch => {
            VerifierErrorReason::VpTokenQueryMismatch
        }
        SdJwtFormatErrorReason::InvalidPresentation
        | SdJwtFormatErrorReason::KeyResolutionFailed
        | SdJwtFormatErrorReason::InvalidCredentialSignature
        | SdJwtFormatErrorReason::IssuerIdentityMismatch
        | SdJwtFormatErrorReason::InvalidHolderBinding => VerifierErrorReason::InvalidBinding,
        // The format error taxonomy is intentionally extensible. New reasons
        // must fail closed until this adapter assigns them a stable mapping.
        _ => VerifierErrorReason::InvalidBinding,
    };
    VerifierError::new(reason)
}

#[cfg(test)]
#[path = "sd_jwt_holder_binding_tests.rs"]
mod tests;
