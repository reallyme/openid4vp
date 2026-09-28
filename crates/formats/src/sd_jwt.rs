// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! RFC 9901 SD-JWT VC verification for OpenID4VP presentations.

use core::fmt;

use reallyme_openid4vp_dcql::{
    credential_satisfies_query, CredentialCandidate, CredentialFormat, CredentialQuery,
    EvaluationCredential,
};
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use reallyme_sd_jwt::{
    parse_sd_jwt_issuer_x5c, verify_sd_jwt, KeyBindingVerificationOptions,
    SdJwtVerificationOptions, VerifiedSdJwt, MAX_SD_JWT_COMPACT_BYTES,
};
use serde_json::Map as JsonMap;
use serde_json::Value as JsonValue;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::parse_transaction_data_binding::parse_transaction_data_binding;
use crate::sd_jwt_error::map_sd_jwt_envelope_error;
use crate::zeroize_json::zeroize_json_value;

const DEFAULT_CLOCK_SKEW_SECONDS: u64 = 60;
const DEFAULT_MAX_FUTURE_IAT_SKEW_SECONDS: u64 = 60;
const DEFAULT_MAX_KB_JWT_AGE_SECONDS: u64 = 300;
const MAX_BINDING_VALUE_BYTES: usize = 8 * 1024;
const SHA256_DIGEST_BYTES: usize = 32;
const SD_JWT_VC_ISSUER_TYP_VALUES: &[&str] = &["dc+sd-jwt"];

#[path = "sd_jwt_trust.rs"]
mod trust;
pub use trust::{SdJwtIssuerIdentity, SdJwtIssuerKeySource, SdJwtVerificationKeyMaterial};

/// Deployment-owned trust and credential-status boundary.
pub trait SdJwtTrustProvider: Send + Sync {
    /// Resolve trusted issuer and holder public keys for a bounded compact value.
    ///
    /// Implementations may inspect unverified JWT headers only to locate
    /// candidate keys. They must apply allowlisted algorithms, bounded network
    /// I/O, authenticated issuer metadata, the query's trusted-authority
    /// constraints, and cache policy before returning.
    /// `now_unix` is the verifier runtime's already-selected evaluation time;
    /// implementations must use it for certificate validity instead of reading
    /// a second ambient clock.
    /// The identity envelope independently verifies that the returned holder
    /// key equals the issuer-signed `cnf.jwk`.
    /// When returning [`SdJwtIssuerKeySource::AuthenticatedX509Header`], the
    /// provider must validate the exact leaf-first `x5c` path from `compact`,
    /// exclude the trust anchor from that header path, reject a self-signed
    /// leaf, and return the authenticated leaf public key. For every source,
    /// the returned issuer identity must be the canonical identifier that the
    /// same trust decision authorizes for the returned key.
    fn resolve_verification_keys(
        &self,
        compact: &str,
        credential_query: &CredentialQuery,
        now_unix: u64,
    ) -> Result<SdJwtVerificationKeyMaterial, SdJwtFormatError>;

    /// Enforce credential status after issuer signature and disclosures verify.
    ///
    /// A credential without a status claim may be accepted unless deployment
    /// policy requires one. A present status claim must never be ignored.
    fn verify_credential_status(
        &self,
        issuer_payload: &JsonValue,
        resolved_payload: &JsonValue,
    ) -> Result<(), SdJwtFormatError>;
}

/// OpenID4VP inputs bound into RFC 9901 key-binding verification.
#[derive(Clone, Copy, PartialEq)]
pub struct SdJwtPresentationVerificationInput<'a> {
    /// Compact SD-JWT VC presentation, including the required KB-JWT.
    pub compact: &'a str,
    /// Full OpenID4VP client identifier expected in the KB-JWT audience.
    pub expected_audience: &'a str,
    /// Authorization-request nonce expected in the KB-JWT.
    pub expected_nonce: &'a str,
    /// Current Unix time supplied by the verifier runtime.
    pub now_unix: u64,
    /// Exact DCQL query associated with this `vp_token` entry.
    pub credential_query: &'a CredentialQuery,
}

impl fmt::Debug for SdJwtPresentationVerificationInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdJwtPresentationVerificationInput")
            .field("compact_byte_len", &self.compact.len())
            .field("audience_byte_len", &self.expected_audience.len())
            .field("nonce_byte_len", &self.expected_nonce.len())
            .field("now_unix", &self.now_unix)
            .field("credential_format", &self.credential_query.format)
            .field("values", &"<redacted>")
            .finish()
    }
}

/// Verified holder-binding claims safe to pass to the verifier engine.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedSdJwtHolderBinding {
    /// KB-JWT audience values.
    pub audience: Vec<String>,
    /// KB-JWT nonce.
    pub nonce: String,
    /// Optional KB-JWT expiration; zero when absent.
    pub expiration_unix: u64,
    /// Required KB-JWT issued-at time.
    pub issued_at_unix: u64,
    /// RFC 9901 SD hash.
    pub sd_hash: String,
    /// Transaction-data digests extracted from the verified KB-JWT.
    pub transaction_data_hashes: Vec<[u8; SHA256_DIGEST_BYTES]>,
    /// Explicit transaction-data hash algorithm when the KB-JWT supplied it.
    pub transaction_data_hashes_alg: Option<TransactionDataHashAlgorithm>,
    /// Disclosure-resolved claims authenticated by the issuer signature.
    pub resolved_payload: JsonValue,
    /// Audited provenance of the issuer verification key.
    pub issuer_key_source: SdJwtIssuerKeySource,
}

impl fmt::Debug for VerifiedSdJwtHolderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedSdJwtHolderBinding")
            .field("audience_count", &self.audience.len())
            .field("expiration_unix", &self.expiration_unix)
            .field("issued_at_unix", &self.issued_at_unix)
            .field(
                "transaction_data_hash_count",
                &self.transaction_data_hashes.len(),
            )
            .field(
                "transaction_data_hashes_alg",
                &self.transaction_data_hashes_alg,
            )
            .field("claim_values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedSdJwtHolderBinding {
    fn zeroize(&mut self) {
        self.audience.zeroize();
        self.nonce.zeroize();
        self.expiration_unix.zeroize();
        self.issued_at_unix.zeroize();
        self.sd_hash.zeroize();
        self.transaction_data_hashes.zeroize();
        self.transaction_data_hashes_alg = None;
        zeroize_json_value(&mut self.resolved_payload);
    }
}

impl Drop for VerifiedSdJwtHolderBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedSdJwtHolderBinding {}

/// SD-JWT VC presentation verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("OpenID4VP SD-JWT format error: {reason:?}")]
pub struct SdJwtFormatError {
    reason: SdJwtFormatErrorReason,
}

impl SdJwtFormatError {
    /// Build an error from a stable, non-sensitive reason.
    pub const fn new(reason: SdJwtFormatErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> SdJwtFormatErrorReason {
        self.reason
    }
}

/// Stable SD-JWT VC error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdJwtFormatErrorReason {
    /// Compact serialization or disclosure processing is invalid.
    InvalidPresentation,
    /// Trusted public-key material could not be resolved.
    KeyResolutionFailed,
    /// Issuer signature or issuer-bound confirmation key is invalid.
    InvalidCredentialSignature,
    /// The signed issuer identifier does not match the identity authenticated
    /// by the issuer-key trust decision.
    IssuerIdentityMismatch,
    /// KB-JWT signature, binding, hash, or temporal claims are invalid.
    InvalidHolderBinding,
    /// Required holder-binding claims are missing or malformed.
    MissingHolderBindingClaim,
    /// Credential status is revoked.
    CredentialRevoked,
    /// Credential status is malformed, inconsistent, or untrusted.
    InvalidCredentialStatus,
    /// Deployment policy requires status information that is unavailable.
    CredentialStatusUnavailable,
    /// Credential validity claims are malformed or outside their accepted time window.
    InvalidCredentialValidity,
    /// The verified credential does not satisfy the associated DCQL query.
    CredentialQueryMismatch,
}

/// Verify issuer signature, disclosures, key binding, time, and status.
pub fn verify_sd_jwt_presentation(
    input: SdJwtPresentationVerificationInput<'_>,
    trust_provider: &(impl SdJwtTrustProvider + ?Sized),
) -> Result<VerifiedSdJwtHolderBinding, SdJwtFormatError> {
    validate_input(input)?;
    let keys = trust_provider.resolve_verification_keys(
        input.compact,
        input.credential_query,
        input.now_unix,
    )?;
    let allow_authenticated_x509_header = match keys.issuer_key_source {
        SdJwtIssuerKeySource::Resolved => false,
        SdJwtIssuerKeySource::AuthenticatedX509Header => {
            parse_sd_jwt_issuer_x5c(input.compact).map_err(|_| {
                SdJwtFormatError::new(SdJwtFormatErrorReason::InvalidCredentialSignature)
            })?;
            true
        }
    };
    let verification_options =
        sd_jwt_verification_options(input, &keys, allow_authenticated_x509_header);
    let verified = verify_sd_jwt(
        input.compact,
        &keys.issuer_jwk,
        keys.issuer_public_key.as_slice(),
        &verification_options,
    )
    .map_err(map_sd_jwt_envelope_error)?;

    validate_issuer_identity(verified_issuer_payload(&verified), &keys.issuer_identity)?;
    validate_issuer_temporal_claims(verified_issuer_payload(&verified), input.now_unix)?;
    trust_provider.verify_credential_status(
        verified_issuer_payload(&verified),
        verified_resolved_payload(&verified),
    )?;
    validate_credential_query(&verified, input.credential_query)?;
    holder_binding_from_verified(&verified, keys.issuer_key_source)
}

fn validate_issuer_identity(
    issuer_payload: &JsonValue,
    trusted_identity: &SdJwtIssuerIdentity,
) -> Result<(), SdJwtFormatError> {
    let signed_issuer = issuer_payload
        .get("iss")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| SdJwtFormatError::new(SdJwtFormatErrorReason::IssuerIdentityMismatch))?;
    if signed_issuer != trusted_identity.as_str() {
        return Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::IssuerIdentityMismatch,
        ));
    }
    Ok(())
}

fn sd_jwt_verification_options<'a>(
    input: SdJwtPresentationVerificationInput<'a>,
    keys: &'a SdJwtVerificationKeyMaterial,
    allow_authenticated_x509_header: bool,
) -> SdJwtVerificationOptions<'a> {
    let mut options = SdJwtVerificationOptions::new(input.now_unix);
    options.issuer_allow_missing_typ = false;
    // The generic verifier remains bound to the caller-supplied key.
    // Embedded material is accepted only after the provider proves that it
    // authenticated this exact x5c path and leaf key.
    options.issuer_allow_embedded_key_header = allow_authenticated_x509_header;
    options.issuer_accepted_typ_values = SD_JWT_VC_ISSUER_TYP_VALUES;
    options.require_key_binding = true;
    options.key_binding = Some(KeyBindingVerificationOptions {
        holder_jwk: &keys.holder_jwk,
        holder_public_key: keys.holder_public_key.as_slice(),
        expected_audience: input.expected_audience,
        expected_nonce: input.expected_nonce,
        now_unix: input.now_unix,
        max_future_iat_skew_seconds: DEFAULT_MAX_FUTURE_IAT_SKEW_SECONDS,
        max_iat_age_seconds: DEFAULT_MAX_KB_JWT_AGE_SECONDS,
    });
    options
}

fn validate_input(input: SdJwtPresentationVerificationInput<'_>) -> Result<(), SdJwtFormatError> {
    if input.compact.is_empty()
        || input.compact.len() > MAX_SD_JWT_COMPACT_BYTES
        || input.expected_audience.is_empty()
        || input.expected_audience.len() > MAX_BINDING_VALUE_BYTES
        || input.expected_nonce.is_empty()
        || input.expected_nonce.len() > MAX_BINDING_VALUE_BYTES
        || input.now_unix == 0
        || input.credential_query.format.as_str() != CredentialFormat::DC_SD_JWT
    {
        return Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::InvalidPresentation,
        ));
    }
    Ok(())
}

fn validate_issuer_temporal_claims(
    issuer_payload: &JsonValue,
    now_unix: u64,
) -> Result<(), SdJwtFormatError> {
    let expiration = optional_numeric_date(issuer_payload, "exp")?;
    let not_before = optional_numeric_date(issuer_payload, "nbf")?;
    let issued_at = optional_numeric_date(issuer_payload, "iat")?;

    // The SD-JWT VC claims are optional, but accepting a present malformed or
    // inapplicable time would turn an issuer restriction into verifier bypass.
    let expiration_floor = now_unix.saturating_sub(DEFAULT_CLOCK_SKEW_SECONDS);
    if expiration.is_some_and(|value| value == 0 || expiration_floor >= value) {
        return Err(invalid_credential_validity());
    }

    let validity_ceiling = now_unix
        .checked_add(DEFAULT_CLOCK_SKEW_SECONDS)
        .ok_or_else(invalid_credential_validity)?;
    if not_before.is_some_and(|value| value == 0 || value > validity_ceiling)
        || issued_at.is_some_and(|value| value == 0 || value > validity_ceiling)
    {
        return Err(invalid_credential_validity());
    }

    Ok(())
}

fn optional_numeric_date(
    payload: &JsonValue,
    claim_name: &str,
) -> Result<Option<u64>, SdJwtFormatError> {
    let Some(value) = payload.get(claim_name) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(invalid_credential_validity)
}

const fn invalid_credential_validity() -> SdJwtFormatError {
    SdJwtFormatError::new(SdJwtFormatErrorReason::InvalidCredentialValidity)
}

fn validate_credential_query(
    verified: &VerifiedSdJwt,
    credential_query: &CredentialQuery,
) -> Result<(), SdJwtFormatError> {
    let has_issuer_confirmation_key = verified_issuer_payload(verified)
        .get("cnf")
        .and_then(JsonValue::as_object)
        .and_then(|confirmation| confirmation.get("jwk"))
        .is_some();
    if credential_query.require_cryptographic_holder_binding && !has_issuer_confirmation_key {
        return Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::CredentialQueryMismatch,
        ));
    }
    let mut meta = JsonMap::new();
    if let Some(vct) = verified_resolved_payload(verified)
        .get("vct")
        .and_then(JsonValue::as_str)
    {
        meta.insert("vct".to_owned(), JsonValue::String(vct.to_owned()));
    }
    let candidate = CredentialCandidate {
        id: EvaluationCredential::new("verified-presentation".to_owned())
            .map_err(|_| SdJwtFormatError::new(SdJwtFormatErrorReason::CredentialQueryMismatch))?,
        format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
            .map_err(|_| SdJwtFormatError::new(SdJwtFormatErrorReason::CredentialQueryMismatch))?,
        meta,
        claims: verified_resolved_payload(verified).clone(),
        // A KB-JWT proves control of its signing key, but only issuer-signed
        // cnf.jwk binds that key to this credential.
        cryptographic_holder_binding: has_issuer_confirmation_key,
    };
    let matches = credential_satisfies_query(credential_query, &candidate)
        .map_err(|_| SdJwtFormatError::new(SdJwtFormatErrorReason::CredentialQueryMismatch))?;
    if !matches {
        return Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::CredentialQueryMismatch,
        ));
    }
    Ok(())
}

fn holder_binding_from_verified(
    verified: &VerifiedSdJwt,
    issuer_key_source: SdJwtIssuerKeySource,
) -> Result<VerifiedSdJwtHolderBinding, SdJwtFormatError> {
    let payload = verified_key_binding_payload(verified)
        .ok_or_else(|| SdJwtFormatError::new(SdJwtFormatErrorReason::MissingHolderBindingClaim))?;
    let audience = parse_audience(payload)?;
    let nonce = required_string(payload, "nonce")?.to_owned();
    let issued_at_unix = payload
        .get("iat")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| SdJwtFormatError::new(SdJwtFormatErrorReason::MissingHolderBindingClaim))?;
    let sd_hash = required_string(payload, "sd_hash")?.to_owned();
    let expiration_unix = payload.get("exp").and_then(JsonValue::as_u64).unwrap_or(0);
    let (transaction_data_hashes, transaction_data_hashes_alg) =
        parse_transaction_data_binding(payload)?;

    Ok(VerifiedSdJwtHolderBinding {
        audience,
        nonce,
        expiration_unix,
        issued_at_unix,
        sd_hash,
        transaction_data_hashes,
        transaction_data_hashes_alg,
        resolved_payload: verified_resolved_payload(verified).clone(),
        issuer_key_source,
    })
}

fn verified_issuer_payload(verified: &VerifiedSdJwt) -> &JsonValue {
    verified.issuer_payload()
}

fn verified_resolved_payload(verified: &VerifiedSdJwt) -> &JsonValue {
    verified.resolved_payload()
}

fn verified_key_binding_payload(verified: &VerifiedSdJwt) -> Option<&JsonValue> {
    verified.key_binding_payload()
}

fn parse_audience(payload: &JsonValue) -> Result<Vec<String>, SdJwtFormatError> {
    match payload.get("aud") {
        Some(JsonValue::String(value)) if !value.is_empty() => Ok(vec![value.clone()]),
        Some(JsonValue::Array(values)) if !values.is_empty() => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|item| !item.is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        SdJwtFormatError::new(SdJwtFormatErrorReason::MissingHolderBindingClaim)
                    })
            })
            .collect(),
        Some(_) | None => Err(SdJwtFormatError::new(
            SdJwtFormatErrorReason::MissingHolderBindingClaim,
        )),
    }
}

fn required_string<'a>(payload: &'a JsonValue, name: &str) -> Result<&'a str, SdJwtFormatError> {
    payload
        .get(name)
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SdJwtFormatError::new(SdJwtFormatErrorReason::MissingHolderBindingClaim))
}

#[cfg(test)]
#[path = "sd_jwt_tests.rs"]
mod tests;
