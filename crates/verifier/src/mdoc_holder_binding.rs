// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_openid4vp_dc_api::{
    build_dc_api_session_transcript, build_redirect_session_transcript,
    CanonicalMdocHandoverCborEncoder, OpenId4VpDcApiHandover, OpenId4VpRedirectHandover,
};
use reallyme_openid4vp_dcql::{ClaimsPathComponent, CredentialFormat};
use reallyme_openid4vp_formats::mdoc::{
    verify_mdoc_presentation, MdocFormatError, MdocFormatErrorReason,
    MdocIssuerCertificateResolver, MdocPresentationVerificationInput, VerifiedMdocPresentation,
    VerifiedMdocStatusReference, MAX_MDOC_PRESENTATION_BYTES,
};
use reallyme_openid4vp_formats::sd_jwt::SdJwtTrustProvider;
use reallyme_openid4vp_types::{PresentationValue, ResponseMode};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    HolderBindingClaims, HolderBindingVerificationContext, HolderBindingVerifier,
    SdJwtHolderBindingVerifier, VerifiedDisclosureSet, VerifiedHolderBinding,
    VerifiedTrustProvenance, VerifierError, VerifierErrorReason,
};

/// Supplies the exact ISO SessionTranscript retained for an active verifier session.
///
/// Redirect and Digital Credentials API handovers require different inputs,
/// including response-key thumbprints or browser origins that are not safely
/// reconstructable from a presentation. The deployment must retain the
/// canonical bytes alongside its one-time session and return only those bytes
/// here; deriving a fresh transcript during response processing would weaken
/// device-authentication binding.
pub trait MdocSessionTranscriptProvider: Send + Sync {
    /// Return zeroizing canonical SessionTranscript CBOR for this session.
    fn session_transcript(
        &self,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, VerifierError>;

    /// Prove that the returned transcript was canonically rebuilt from this
    /// session's client identifier, nonce, transport binding, and response-key
    /// thumbprint or browser origin.
    ///
    /// Implementations must compare canonical bytes in constant time. Merely
    /// loading caller-supplied bytes from the session is insufficient because
    /// it does not show that those bytes commit to the active request.
    fn validate_session_binding(
        &self,
        context: HolderBindingVerificationContext<'_>,
        session_transcript_cbor: &[u8],
    ) -> Result<(), VerifierError>;
}

/// Production provider that rebuilds the transcript from persisted session binding.
///
/// Keeping this adapter in the protocol crate gives service hosts one audited
/// path and prevents them from re-deriving handover inputs during response
/// processing.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetainedMdocSessionTranscriptProvider;

impl MdocSessionTranscriptProvider for RetainedMdocSessionTranscriptProvider {
    fn session_transcript(
        &self,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, VerifierError> {
        context
            .session()
            .mdoc_session_transcript
            .as_ref()
            .map(|transcript| Zeroizing::new(transcript.as_bytes().to_vec()))
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidBinding))
    }

    fn validate_session_binding(
        &self,
        context: HolderBindingVerificationContext<'_>,
        session_transcript_cbor: &[u8],
    ) -> Result<(), VerifierError> {
        let session = context.session();
        let retained = session
            .mdoc_session_transcript
            .as_ref()
            .ok_or_else(invalid_binding)?;
        let thumbprint = retained.response_key_thumbprint_sha256().copied();
        let rebuilt = match session.response_mode {
            ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
                let response_uri = session
                    .binding
                    .response_uri
                    .clone()
                    .ok_or_else(invalid_binding)?;
                build_redirect_session_transcript(
                    OpenId4VpRedirectHandover {
                        client_id: session.binding.client_id.clone(),
                        nonce: session.binding.nonce.clone(),
                        jwk_thumbprint_sha256: thumbprint,
                        response_uri,
                    },
                    &CanonicalMdocHandoverCborEncoder,
                )
                .map_err(|_| invalid_binding())?
            }
            ResponseMode::DcApi | ResponseMode::DcApiJwt => {
                let origin = session
                    .binding
                    .dc_api_origin
                    .clone()
                    .ok_or_else(invalid_binding)?;
                build_dc_api_session_transcript(
                    OpenId4VpDcApiHandover {
                        origin,
                        nonce: session.binding.nonce.clone(),
                        jwk_thumbprint_sha256: thumbprint,
                    },
                    &CanonicalMdocHandoverCborEncoder,
                )
                .map_err(|_| invalid_binding())?
            }
            ResponseMode::Fragment | ResponseMode::FormPost => return Err(invalid_binding()),
        };
        if bool::from(rebuilt.as_bytes().ct_eq(session_transcript_cbor)) {
            Ok(())
        } else {
            Err(invalid_binding())
        }
    }
}

const fn invalid_binding() -> VerifierError {
    VerifierError::new(VerifierErrorReason::InvalidBinding)
}

/// Production mdoc adapter for verifier response validation.
pub struct MdocHolderBindingVerifier<'a> {
    issuer_certificate_resolver: &'a dyn MdocIssuerCertificateResolver,
    session_transcript_provider: &'a dyn MdocSessionTranscriptProvider,
    status_verifier: &'a dyn MdocStatusVerifier,
}

/// Result of checking one authenticated mdoc status reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdocStatusDecision {
    /// Credential is active according to a fresh, authenticated response.
    Valid,
    /// Credential is revoked.
    Revoked,
    /// Status response was malformed, inconsistent, or unauthenticated.
    Invalid,
    /// Status service could not provide a decision.
    Unavailable,
    /// Status response is outside its authenticated freshness interval.
    Stale,
}

/// Host port for resolving authenticated ISO mdoc status references.
pub trait MdocStatusVerifier: Send + Sync {
    /// Check one MSO-authenticated reference at the trusted verification time.
    fn verify_status(
        &self,
        reference: &VerifiedMdocStatusReference,
        now_unix: u64,
    ) -> MdocStatusDecision;
}

impl<'a> MdocHolderBindingVerifier<'a> {
    /// Bind mdoc verification to deployment trust and one-time session state.
    #[must_use]
    pub const fn new(
        issuer_certificate_resolver: &'a dyn MdocIssuerCertificateResolver,
        session_transcript_provider: &'a dyn MdocSessionTranscriptProvider,
        status_verifier: &'a dyn MdocStatusVerifier,
    ) -> Self {
        Self {
            issuer_certificate_resolver,
            session_transcript_provider,
            status_verifier,
        }
    }
}

impl HolderBindingVerifier for MdocHolderBindingVerifier<'_> {
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        if context.credential_query().format.as_str() != CredentialFormat::MSO_MDOC {
            return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
        }
        let PresentationValue::Compact(encoded) = presentation else {
            return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
        };
        let encoded_limit = MAX_MDOC_PRESENTATION_BYTES
            .checked_mul(2)
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
        if encoded.len() > encoded_limit {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
        let device_response = Zeroizing::new(
            base64url_to_bytes(encoded)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?,
        );
        if device_response.len() > MAX_MDOC_PRESENTATION_BYTES {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
        let session_transcript = self
            .session_transcript_provider
            .session_transcript(context)?;
        if session_transcript.is_empty() {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
        self.session_transcript_provider
            .validate_session_binding(context, &session_transcript)?;
        let verified = verify_mdoc_presentation(
            MdocPresentationVerificationInput {
                device_response_cbor: &device_response,
                session_transcript_cbor: &session_transcript,
                now_unix: context.now_unix(),
            },
            self.issuer_certificate_resolver,
        )
        .map_err(map_mdoc_error)?;
        validate_mdoc_status(&verified, self.status_verifier, context.now_unix())?;
        validate_document_type(context, &verified.document_types)?;
        validate_supported_mdoc_query(context, &verified)?;

        let claims = HolderBindingClaims {
            audience: vec![context
                .session()
                .binding
                .dc_api_origin
                .as_ref()
                .map_or_else(
                    || context.session().binding.client_id.to_wire_value(),
                    |origin| ["origin:", origin.as_str()].concat(),
                )],
            nonce: context.session().binding.nonce.clone(),
            expiration_unix: 0,
            issued_at_unix: 0,
            sd_hash: None,
            transaction_data_hashes: Vec::new(),
            transaction_data_hashes_alg: None,
        };
        Ok(VerifiedHolderBinding::new(
            claims,
            VerifiedDisclosureSet::Mdoc(verified.disclosed_claims.clone()),
            VerifiedTrustProvenance::MdocIssuerCertificate,
        ))
    }
}

fn validate_mdoc_status(
    verified: &VerifiedMdocPresentation,
    status_verifier: &dyn MdocStatusVerifier,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if verified.has_unsupported_status_extension {
        return Err(VerifierError::new(
            VerifierErrorReason::InvalidCredentialStatus,
        ));
    }
    for reference in &verified.status_references {
        let reason = match status_verifier.verify_status(reference, now_unix) {
            MdocStatusDecision::Valid => continue,
            MdocStatusDecision::Revoked => VerifierErrorReason::CredentialRevoked,
            MdocStatusDecision::Invalid | MdocStatusDecision::Stale => {
                VerifierErrorReason::InvalidCredentialStatus
            }
            MdocStatusDecision::Unavailable => VerifierErrorReason::CredentialStatusUnavailable,
        };
        return Err(VerifierError::new(reason));
    }
    Ok(())
}

fn validate_supported_mdoc_query(
    context: HolderBindingVerificationContext<'_>,
    verified: &VerifiedMdocPresentation,
) -> Result<(), VerifierError> {
    let query = context.credential_query();
    if query.claim_sets.is_some() || query.trusted_authorities.is_some() {
        // Claim-set alternatives and trust-framework identifiers need their
        // own authenticated evaluation models. Never treat simple claim
        // presence or an issuer certificate path as a substitute.
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    let Some(claims) = query.claims.as_ref() else {
        return Ok(());
    };
    for claim in claims {
        if claim.values.is_some() {
            // Raw PID values deliberately remain in the verified mdoc envelope.
            // Exact-value constraints require a typed, privacy-preserving value
            // comparator rather than exposing them through generic metadata.
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenQueryMismatch,
            ));
        }
        let [ClaimsPathComponent::Name(namespace), ClaimsPathComponent::Name(element_identifier)] =
            claim.path.components()
        else {
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenQueryMismatch,
            ));
        };
        if !verified.disclosed_claims.iter().any(|disclosed| {
            disclosed.document_index == 0
                && disclosed.namespace == *namespace
                && disclosed.element_identifier == *element_identifier
        }) {
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenQueryMismatch,
            ));
        }
    }
    Ok(())
}

/// Production dispatcher for both HAIP credential formats.
pub struct OpenId4VpHolderBindingVerifier<'a> {
    sd_jwt: SdJwtHolderBindingVerifier<'a>,
    mdoc: MdocHolderBindingVerifier<'a>,
}

impl<'a> OpenId4VpHolderBindingVerifier<'a> {
    /// Construct a verifier that dispatches only from the validated DCQL format.
    #[must_use]
    pub const fn new(
        sd_jwt_trust_provider: &'a dyn SdJwtTrustProvider,
        mdoc_issuer_certificate_resolver: &'a dyn MdocIssuerCertificateResolver,
        mdoc_session_transcript_provider: &'a dyn MdocSessionTranscriptProvider,
        mdoc_status_verifier: &'a dyn MdocStatusVerifier,
    ) -> Self {
        Self {
            sd_jwt: SdJwtHolderBindingVerifier::new(sd_jwt_trust_provider),
            mdoc: MdocHolderBindingVerifier::new(
                mdoc_issuer_certificate_resolver,
                mdoc_session_transcript_provider,
                mdoc_status_verifier,
            ),
        }
    }
}

impl HolderBindingVerifier for OpenId4VpHolderBindingVerifier<'_> {
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        match context.credential_query().format.as_str() {
            CredentialFormat::DC_SD_JWT => self.sd_jwt.verify_holder_binding(presentation, context),
            CredentialFormat::MSO_MDOC => self.mdoc.verify_holder_binding(presentation, context),
            _ => Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat)),
        }
    }
}

fn validate_document_type(
    context: HolderBindingVerificationContext<'_>,
    document_types: &[String],
) -> Result<(), VerifierError> {
    let expected = context
        .credential_query()
        .meta
        .get("doctype_value")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
    if document_types.len() != 1 || document_types.first().map(String::as_str) != Some(expected) {
        return Err(VerifierError::new(
            VerifierErrorReason::VpTokenQueryMismatch,
        ));
    }
    Ok(())
}

fn map_mdoc_error(error: MdocFormatError) -> VerifierError {
    let reason = match error.reason() {
        MdocFormatErrorReason::Expired => VerifierErrorReason::HolderBindingExpired,
        MdocFormatErrorReason::SessionTranscriptMismatch => VerifierErrorReason::SessionMismatch,
        MdocFormatErrorReason::DocumentTypeMismatch => VerifierErrorReason::VpTokenQueryMismatch,
        MdocFormatErrorReason::InvalidDeviceResponse
        | MdocFormatErrorReason::InvalidIssuerAuthentication
        | MdocFormatErrorReason::InvalidDeviceAuthentication
        | MdocFormatErrorReason::UnsupportedOperation => VerifierErrorReason::InvalidBinding,
        _ => VerifierErrorReason::InvalidBinding,
    };
    VerifierError::new(reason)
}

#[cfg(test)]
#[path = "mdoc_holder_binding_tests.rs"]
mod tests;
