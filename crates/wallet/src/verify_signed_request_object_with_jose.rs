// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientIdentifierPrefix, ResponseMode,
};
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BoundedX509CertificateChain, RequestObjectSignatureVerifier, VerifiedClientIdentifierBinding,
    VerifiedClientMetadataReference, VerifiedRequestObject, VerifiedVerifierAttestation,
    VerifiedX509CertificateBinding, WalletError, WalletErrorReason, WalletInvocationContext,
    WalletRequestTrustEvidence, X509RequestObjectTrustDecision,
};

#[path = "verify_signed_request_object_with_jose/header.rs"]
mod header;

use header::{parse_embedded_key_header, validate_compact_jws_envelope, EmbeddedKeyHeader};

const REQUEST_OBJECT_TYP_VALUES: &[&str] = &["oauth-authz-req+jwt"];
const REQUEST_OBJECT_CLOCK_SKEW_SECONDS: u64 = 60;
const REQUEST_OBJECT_MAX_FUTURE_IAT_SKEW_SECONDS: u64 = 60;

/// Atomic verification material and trust decision for one exact Request Object.
pub struct JoseRequestObjectVerification {
    jwk: reallyme_crypto::jwk::Jwk,
    public_key: Zeroizing<Vec<u8>>,
    client_identifier_binding: Option<VerifiedClientIdentifierBinding>,
    verifier_attestation: Option<VerifiedVerifierAttestation>,
    client_metadata_reference: Option<VerifiedClientMetadataReference>,
    x509_trust_decision: Option<X509RequestObjectTrustDecision>,
}

impl fmt::Debug for JoseRequestObjectVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoseRequestObjectVerification")
            .field(
                "has_client_identifier_binding",
                &self.client_identifier_binding.is_some(),
            )
            .field(
                "has_verifier_attestation",
                &self.verifier_attestation.is_some(),
            )
            .field(
                "has_metadata_reference",
                &self.client_metadata_reference.is_some(),
            )
            .field("has_x509_trust", &self.x509_trust_decision.is_some())
            .field("key_material", &"<redacted>")
            .finish()
    }
}

impl JoseRequestObjectVerification {
    /// Build an atomic result from verification material owned by this result.
    ///
    /// Ownership is required because an X.509 resolver derives the verification
    /// key from the exact attacker-supplied chain after validating it. Borrowing
    /// here would force the resolver to retain unbounded request-specific state.
    pub fn new(jwk: reallyme_crypto::jwk::Jwk, public_key: Vec<u8>) -> Self {
        Self {
            jwk,
            public_key: Zeroizing::new(public_key),
            client_identifier_binding: None,
            verifier_attestation: None,
            client_metadata_reference: None,
            x509_trust_decision: None,
        }
    }

    /// Attach a completed DID verification-method or federation entity/key decision.
    #[must_use]
    pub fn with_client_identifier_binding(
        mut self,
        evidence: VerifiedClientIdentifierBinding,
    ) -> Self {
        self.client_identifier_binding = Some(evidence);
        self
    }

    /// Attach a verified attestation bound to this exact signature key.
    #[must_use]
    pub fn with_verifier_attestation(mut self, evidence: VerifiedVerifierAttestation) -> Self {
        self.verifier_attestation = Some(evidence);
        self
    }

    /// Attach fresh metadata evidence resolved for this exact Request Object.
    #[must_use]
    pub fn with_client_metadata_reference(
        mut self,
        evidence: VerifiedClientMetadataReference,
    ) -> Self {
        self.client_metadata_reference = Some(evidence);
        self
    }

    /// Attach the host evaluator's typed result for the exact `x5c` chain.
    #[must_use]
    pub fn with_x509_trust_decision(mut self, decision: X509RequestObjectTrustDecision) -> Self {
        self.x509_trust_decision = Some(decision);
        self
    }

    fn into_evidence(
        self,
        header_chain: Option<&BoundedX509CertificateChain>,
        verified_client_id: Option<&ClientIdentifier>,
        now_unix: u64,
    ) -> Result<WalletRequestTrustEvidence, WalletError> {
        if self
            .verifier_attestation
            .as_ref()
            .is_some_and(|attestation| {
                !attestation.validates_signing_key(self.public_key.as_slice(), now_unix)
            })
        {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        }
        let x509_certificate_binding = match (self.x509_trust_decision, header_chain) {
            (Some(decision), Some(chain)) => {
                let binding = VerifiedX509CertificateBinding::from_trust_decision(
                    decision,
                    self.public_key.as_slice(),
                    now_unix,
                )?;
                if !binding.matches_chain(chain) {
                    return Err(WalletError::new(WalletErrorReason::X509LeafKeyMismatch));
                }
                Some(binding)
            }
            (Some(_), None) => {
                return Err(WalletError::new(
                    WalletErrorReason::MissingX509CertificateChain,
                ));
            }
            (None, _) => None,
        };
        if let Some(binding) = self.client_identifier_binding.as_ref() {
            let Some(client_id) = verified_client_id else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidClientIdentifierTrustBinding,
                ));
            };
            if !binding.validates(client_id, self.public_key.as_slice()) {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidClientIdentifierTrustBinding,
                ));
            }
        }
        Ok(WalletRequestTrustEvidence {
            client_identifier_binding: self.client_identifier_binding,
            verifier_attestation: self.verifier_attestation,
            client_metadata_reference: self.client_metadata_reference,
            x509_certificate_binding,
        })
    }
}

/// Resolves an atomic key-and-trust result for a signed OpenID4VP Request Object.
///
/// For X.509 client identifiers, the resolver must evaluate the supplied
/// leaf-first chain for an explicit deployment-selected purpose and return the
/// decision in the same result as the leaf verification key. The adapter
/// subsequently proves that the result refers to the exact RFC 7515 Section
/// 4.1.6 `x5c` bytes.
pub trait JoseRequestObjectVerificationResolver: Send + Sync {
    /// Resolve the key and all trust evidence for the exact compact JWT.
    fn resolve_request_object_verification(
        &self,
        jwt: &str,
        claimed_client_identifier: Option<&ClientIdentifier>,
        x509_chain: Option<&BoundedX509CertificateChain>,
        now_unix: u64,
    ) -> Result<JoseRequestObjectVerification, WalletError>;
}

/// `reallyme-jose` backed verifier for signed RFC 9101 Request Objects.
pub struct JoseSignedRequestObjectVerifier<R> {
    resolver: R,
    expected_audience: Zeroizing<String>,
    temporal_policy: reallyme_jose::jwt::JwtTemporalValidationPolicy,
    header_validation: reallyme_jose::jwt::JwtHeaderValidationOptions<'static>,
}

impl<R> JoseSignedRequestObjectVerifier<R> {
    /// Build a verifier with the OpenID4VP signed Request Object policy.
    pub fn new(resolver: R, expected_audience: String) -> Self {
        Self {
            resolver,
            expected_audience: Zeroizing::new(expected_audience),
            temporal_policy: request_object_temporal_policy(),
            header_validation: request_object_header_validation(),
        }
    }
}

impl<R> RequestObjectSignatureVerifier for JoseSignedRequestObjectVerifier<R>
where
    R: JoseRequestObjectVerificationResolver,
{
    fn verify_request_object(
        &self,
        jwt: &str,
        invocation: &WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        self.verify_request_object_with_client_identifier(jwt, None, invocation, now_unix)
    }
}

impl<R> JoseSignedRequestObjectVerifier<R>
where
    R: JoseRequestObjectVerificationResolver,
{
    pub(crate) fn verify_request_object_with_client_identifier(
        &self,
        jwt: &str,
        protected_client_id: Option<&ClientIdentifier>,
        invocation: &WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        validate_compact_jws_envelope(jwt)?;
        let embedded_header = parse_embedded_key_header(jwt)?;
        let mut unverified_request = unverified_request_hint(jwt)
            .ok_or_else(|| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
        validate_invocation_hint(unverified_request.response_mode, invocation)?;
        let claimed_client_identifier = protected_client_id
            .cloned()
            .or_else(|| unverified_request.client_id.take());
        let verification = self.resolver.resolve_request_object_verification(
            jwt,
            claimed_client_identifier.as_ref(),
            embedded_header.x509_chain.as_ref(),
            now_unix,
        )?;
        let claims_policy = reallyme_jose::jwt::JwtClaimsValidationPolicy::new(
            self.temporal_policy,
            self.expected_audience.as_str(),
            None,
            None,
        );
        let mut request: AuthorizationRequestObject =
            reallyme_jose::jwt::decode_verify_jwt_with_claims_validation_and_header_validation(
                jwt,
                &verification.jwk,
                verification.public_key.as_slice(),
                now_unix,
                claims_policy,
                &self.header_validation,
            )
            .map_err(map_jwt_verification_error)?;
        if let Some(client_id) = protected_client_id {
            if request.client_id.is_some() {
                return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
            }
            request.client_id = Some(client_id.clone());
        }
        validate_embedded_key_header_profile(&embedded_header, &request)?;
        if uses_x509_client_identifier(&request) && verification.x509_trust_decision.is_none() {
            return Err(WalletError::new(
                WalletErrorReason::X509TrustEvidenceUnavailable,
            ));
        }
        let evidence = verification.into_evidence(
            embedded_header.x509_chain.as_ref(),
            request.client_id.as_ref(),
            now_unix,
        )?;
        Ok(VerifiedRequestObject::new_with_temporal_policy(
            request,
            evidence,
            self.temporal_policy.max_future_iat_skew_seconds(),
        ))
    }
}

#[derive(Deserialize)]
struct UnverifiedRequestHint {
    client_id: Option<ClientIdentifier>,
    response_mode: Option<ResponseMode>,
}

impl Drop for UnverifiedRequestHint {
    fn drop(&mut self) {
        self.client_id.zeroize();
        self.response_mode = None;
    }
}

fn unverified_request_hint(jwt: &str) -> Option<UnverifiedRequestHint> {
    const MAX_REQUEST_OBJECT_PAYLOAD_BYTES: usize = 64 * 1024;

    let payload = jwt.split('.').nth(1)?;
    let mut decoded = reallyme_codec::base64url::base64url_to_bytes(payload).ok()?;
    if decoded.len() > MAX_REQUEST_OBJECT_PAYLOAD_BYTES {
        decoded.zeroize();
        return None;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&decoded);
    let parsed = UnverifiedRequestHint::deserialize(&mut deserializer)
        .ok()
        .filter(|_| deserializer.end().is_ok());
    decoded.zeroize();
    parsed
}

fn validate_invocation_hint(
    response_mode: Option<ResponseMode>,
    invocation: &WalletInvocationContext,
) -> Result<(), WalletError> {
    let is_dc_api = matches!(
        response_mode,
        Some(
            reallyme_openid4vp_types::ResponseMode::DcApi
                | reallyme_openid4vp_types::ResponseMode::DcApiJwt
        )
    );
    if is_dc_api != invocation.expected_origin().is_some() {
        return Err(WalletError::new(WalletErrorReason::InvalidPlatformOrigin));
    }
    Ok(())
}

const fn request_object_header_validation(
) -> reallyme_jose::jwt::JwtHeaderValidationOptions<'static> {
    // OpenID4VP 1.0 Final Section 5.9.3 requires the RFC 7515 `x5c`
    // parameter for both X.509 client identifier prefixes. The profile check
    // below permits it only for those prefixes and always rejects `jwk`.
    reallyme_jose::jwt::JwtHeaderValidationOptions::new(false, true, REQUEST_OBJECT_TYP_VALUES)
}

const fn request_object_temporal_policy() -> reallyme_jose::jwt::JwtTemporalValidationPolicy {
    // OpenID4VP Request Objects do not make exp, nbf, or iat mandatory.  The
    // generic JOSE strict policy requires exp and would reject conforming OIDF
    // Request Objects that omit every temporal claim.  Optional claims still
    // receive bounded validation when a verifier includes them.
    reallyme_jose::jwt::JwtTemporalValidationPolicy::new(
        false,
        false,
        false,
        REQUEST_OBJECT_CLOCK_SKEW_SECONDS,
        REQUEST_OBJECT_MAX_FUTURE_IAT_SKEW_SECONDS,
    )
}

fn validate_embedded_key_header_profile(
    header: &EmbeddedKeyHeader,
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    if header.has_jwk {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    let uses_x509_client_identifier = uses_x509_client_identifier(request);
    match (header.x509_chain.is_some(), uses_x509_client_identifier) {
        (false, true) => Err(WalletError::new(
            WalletErrorReason::MissingX509CertificateChain,
        )),
        (true, false) => Err(WalletError::new(WalletErrorReason::InvalidRequestObject)),
        (false, false) | (true, true) => Ok(()),
    }
}

fn uses_x509_client_identifier(request: &AuthorizationRequestObject) -> bool {
    request.client_id.as_ref().is_some_and(|client_id| {
        matches!(
            client_id.prefix(),
            ClientIdentifierPrefix::X509SanDns | ClientIdentifierPrefix::X509Hash
        )
    })
}

fn map_jwt_verification_error(error: reallyme_jose::jwt::JwtError) -> WalletError {
    use reallyme_jose::jwt::JwtError;

    let reason = match error {
        JwtError::InputTooLarge | JwtError::LengthOverflow => {
            WalletErrorReason::RequestObjectTooLarge
        }
        JwtError::Expired => WalletErrorReason::RequestObjectExpired,
        JwtError::NotYetValid | JwtError::IssuedAtInFuture => {
            WalletErrorReason::RequestObjectIssuedInFuture
        }
        JwtError::InvalidSignature
        | JwtError::KeyIdMismatch
        | JwtError::PublicKeyMismatch
        | JwtError::MissingPublicKey
        | JwtError::InvalidPublicKey
        | JwtError::Crypto => WalletErrorReason::InvalidRequestObjectSignature,
        JwtError::UnsupportedAlgorithm
        | JwtError::AlgorithmMismatch
        | JwtError::MissingAlgorithm => WalletErrorReason::UnsupportedRequestObjectAlgorithm,
        JwtError::InvalidJwtFormat
        | JwtError::InvalidHeader
        | JwtError::InvalidClaims
        | JwtError::SigningKeyMismatch
        | JwtError::MissingPrivateKey
        | JwtError::Serialization
        | JwtError::Base64Url
        | JwtError::MissingRequiredTemporalClaim(_)
        | JwtError::InvalidTemporalClaimValue(_)
        | JwtError::InvalidVerificationTime
        | JwtError::InvalidTemporalPolicy
        | JwtError::MissingRequiredRegisteredClaim(_)
        | JwtError::InvalidRegisteredClaimValue(_)
        | JwtError::AudienceMismatch
        | JwtError::IssuerMismatch
        | JwtError::SubjectMismatch
        | JwtError::InvalidClaimsPolicy => WalletErrorReason::InvalidRequestObject,
        _ => WalletErrorReason::InvalidRequestObject,
    };
    WalletError::new(reason)
}

#[cfg(test)]
#[path = "verify_signed_request_object_with_jose_tests.rs"]
mod tests;
