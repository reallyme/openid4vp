// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! ISO mdoc presentation glue for OpenID4VP.
//!
//! ISO 18013-5 `DeviceResponse` decoding and verification is delegated to
//! `reallyme/ssi`'s `reallyme-mdoc` crate. This module owns only the
//! OpenID4VP-facing adapter boundary so format verification can be injected into
//! verifier flows without duplicating CBOR structures.

use core::fmt;

use reallyme_mdoc::{
    decode_issuer_signed_item, verify_mdoc_device_response_with_x5chain, IssuerNameSpaces,
    MdocCertificatePathValidation as SsiMdocCertificatePathValidation, MdocEnvelopeError,
    MdocInvalidInputReason, VerifiedMdoc, VerifiedMdocDeviceResponse,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum decoded mdoc DeviceResponse size accepted by the SSI envelope.
pub const MAX_MDOC_PRESENTATION_BYTES: usize = reallyme_mdoc::MAX_MDOC_CBOR_INPUT_BYTES;

/// OpenID4VP mdoc presentation verification input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MdocPresentationVerificationInput<'a> {
    /// ISO 18013-5 DeviceResponse CBOR bytes supplied as an OpenID4VP
    /// `mso_mdoc` presentation.
    pub device_response_cbor: &'a [u8],
    /// SessionTranscript CBOR bytes constructed by `crates/dc-api` for the
    /// active OpenID4VP redirect or Digital Credentials API handover.
    pub session_transcript_cbor: &'a [u8],
    /// Unix timestamp used for both certificate-path and MSO validity checks.
    pub now_unix: u64,
}

impl fmt::Debug for MdocPresentationVerificationInput<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdocPresentationVerificationInput")
            .field("device_response_byte_len", &self.device_response_cbor.len())
            .field(
                "session_transcript_byte_len",
                &self.session_transcript_cbor.len(),
            )
            .field("now_unix", &self.now_unix)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Result of validating an mdoc document-signer certificate path.
///
/// The certificate interval is retained alongside the public key because the
/// signed MSO time must fall within the authenticated document-signer
/// certificate lifetime. Keeping this richer result at the OpenID4VP trust
/// boundary avoids reducing path validation to a bare-key lookup.
pub struct MdocCertificatePathValidation {
    /// P-256 document-signer public key bytes.
    pub public_key: Vec<u8>,
    /// Inclusive certificate validity start as Unix seconds.
    pub not_before_unix: u64,
    /// Inclusive certificate validity end as Unix seconds.
    pub not_after_unix: u64,
    /// Inclusive IACA trust-anchor validity start as Unix seconds.
    pub iaca_not_before_unix: u64,
    /// Inclusive IACA trust-anchor validity end as Unix seconds.
    pub iaca_not_after_unix: u64,
}

impl fmt::Debug for MdocCertificatePathValidation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdocCertificatePathValidation")
            .field("public_key_byte_len", &self.public_key.len())
            .field("not_before_unix", &self.not_before_unix)
            .field("not_after_unix", &self.not_after_unix)
            .field("iaca_not_before_unix", &self.iaca_not_before_unix)
            .field("iaca_not_after_unix", &self.iaca_not_after_unix)
            .field("public_key", &"<redacted>")
            .finish()
    }
}

/// X.509 trust boundary for mdoc issuer authentication.
pub trait MdocIssuerCertificateResolver: Send + Sync {
    /// Validate the RFC 9360 leaf-first certificate path.
    ///
    /// Implementations must perform certificate parsing, path and profile
    /// validation, revocation policy, and trust-anchor selection at the
    /// supplied authenticated MSO signing time. Returning a key extracted from
    /// an otherwise untrusted leaf certificate is unsafe.
    fn validate_issuer_certificate_path(
        &self,
        certificate_path_der: &[Vec<u8>],
        mso_signing_time_unix: u64,
    ) -> Option<MdocCertificatePathValidation>;
}

/// OpenID4VP-owned result of successful mdoc presentation verification.
///
/// The identity envelope crate owns the ISO 18013-5 CBOR model and disclosed
/// claim structures. This result intentionally exposes only protocol-safe
/// verification metadata so OpenID4VP consumers do not depend on unpublished
/// envelope types through this crate's public API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMdocPresentation {
    /// Number of verified documents in the DeviceResponse.
    pub document_count: usize,
    /// Verified document types in DeviceResponse order.
    pub document_types: Vec<String>,
    /// Issuer-authenticated claim identifiers disclosed by each document.
    ///
    /// Values remain inside the verified mdoc envelope so this metadata cannot
    /// accidentally move PID data into logs or generic protocol diagnostics.
    pub disclosed_claims: Vec<VerifiedMdocClaim>,
    /// Status references authenticated inside each verified MSO.
    pub status_references: Vec<VerifiedMdocStatusReference>,
    /// True when an authenticated status map contains an extension this layer
    /// cannot safely enforce. Callers must fail closed in this case.
    pub has_unsupported_status_extension: bool,
}

impl Zeroize for VerifiedMdocPresentation {
    fn zeroize(&mut self) {
        self.document_count.zeroize();
        self.document_types.zeroize();
        self.disclosed_claims.zeroize();
        self.status_references.zeroize();
        self.has_unsupported_status_extension.zeroize();
    }
}

impl Drop for VerifiedMdocPresentation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedMdocPresentation {}

/// One issuer-authenticated mdoc claim identifier.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct VerifiedMdocClaim {
    /// Zero-based index into [`VerifiedMdocPresentation::document_types`].
    pub document_index: usize,
    /// ISO mdoc namespace containing the disclosed element.
    pub namespace: String,
    /// ISO mdoc data element identifier.
    pub element_identifier: String,
}

/// Authenticated ISO mdoc status reference projected from an MSO.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub enum VerifiedMdocStatusReference {
    /// Index-based status list reference.
    StatusList {
        /// Zero-based status-list index.
        index: u64,
        /// Absolute status-list URI.
        uri: String,
        /// Optional status-list certificate authenticated by the MSO.
        certificate_der: Option<Vec<u8>>,
    },
    /// Identifier-based status list reference.
    IdentifierList {
        /// Credential identifier authenticated by the MSO.
        identifier: Vec<u8>,
        /// Absolute identifier-list URI.
        uri: String,
        /// Optional list certificate authenticated by the MSO.
        certificate_der: Option<Vec<u8>>,
    },
}

impl Drop for VerifiedMdocStatusReference {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedMdocStatusReference {}

/// OpenID4VP mdoc verification error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("OpenID4VP mdoc format error: {reason:?}")]
pub struct MdocFormatError {
    reason: MdocFormatErrorReason,
}

impl MdocFormatError {
    /// Build an mdoc format error from a stable reason.
    pub const fn new(reason: MdocFormatErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> MdocFormatErrorReason {
        self.reason
    }
}

/// Stable OpenID4VP mdoc format error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdocFormatErrorReason {
    /// DeviceResponse bytes were empty or malformed.
    InvalidDeviceResponse,
    /// IssuerAuth signature or issuer-signed digests failed verification.
    InvalidIssuerAuthentication,
    /// DeviceAuth signature failed verification.
    InvalidDeviceAuthentication,
    /// DeviceAuthentication did not bind the expected OpenID4VP SessionTranscript.
    SessionTranscriptMismatch,
    /// mdoc document type in the DeviceResponse does not match signed content.
    DocumentTypeMismatch,
    /// DeviceResponse or MobileSecurityObject was expired for the supplied time.
    Expired,
    /// The identity mdoc provider does not support the requested operation.
    UnsupportedOperation,
}

/// Verify an OpenID4VP mdoc presentation through the identity mdoc envelope.
pub fn verify_mdoc_presentation(
    input: MdocPresentationVerificationInput<'_>,
    resolver: &(impl MdocIssuerCertificateResolver + ?Sized),
) -> Result<VerifiedMdocPresentation, MdocFormatError> {
    if input.device_response_cbor.is_empty() {
        return Err(MdocFormatError::new(
            MdocFormatErrorReason::InvalidDeviceResponse,
        ));
    }
    if input.session_transcript_cbor.is_empty() {
        return Err(MdocFormatError::new(
            MdocFormatErrorReason::SessionTranscriptMismatch,
        ));
    }

    let verified = verify_mdoc_device_response_with_x5chain(
        input.device_response_cbor,
        |certificate_path_der, mso_signing_time_unix| {
            let validation = resolver
                .validate_issuer_certificate_path(certificate_path_der, mso_signing_time_unix)?;
            Some(SsiMdocCertificatePathValidation {
                public_key: validation.public_key,
                not_before_unix: validation.not_before_unix,
                not_after_unix: validation.not_after_unix,
                iaca_not_before_unix: validation.iaca_not_before_unix,
                iaca_not_after_unix: validation.iaca_not_after_unix,
            })
        },
        input.session_transcript_cbor,
        input.now_unix,
    )
    .map_err(map_mdoc_envelope_error)?;

    let mut disclosed_claims = Vec::new();
    let documents = verified_mdoc_documents(&verified);
    for (document_index, document) in documents.iter().enumerate() {
        let Some(namespaces) = verified_mdoc_namespaces(document) else {
            continue;
        };
        for (namespace, items) in namespaces {
            for tagged in items {
                let item = decode_issuer_signed_item(tagged).map_err(|_| {
                    MdocFormatError::new(MdocFormatErrorReason::InvalidIssuerAuthentication)
                })?;
                if disclosed_claims.iter().any(|claim: &VerifiedMdocClaim| {
                    claim.document_index == document_index
                        && claim.namespace == *namespace
                        && claim.element_identifier == item.element_identifier
                }) {
                    return Err(MdocFormatError::new(
                        MdocFormatErrorReason::InvalidIssuerAuthentication,
                    ));
                }
                disclosed_claims.push(VerifiedMdocClaim {
                    document_index,
                    namespace: namespace.clone(),
                    element_identifier: item.element_identifier.clone(),
                });
            }
        }
    }

    let mut status_references = Vec::new();
    let mut has_unsupported_status_extension = false;
    for document in documents {
        let Some(status) = document.mobile_security_object().status.as_ref() else {
            continue;
        };
        has_unsupported_status_extension |= !status.extensions().is_empty();
        if let Some(reference) = status.status_list_ref() {
            has_unsupported_status_extension |= !reference.extensions().is_empty();
            status_references.push(VerifiedMdocStatusReference::StatusList {
                index: reference.index(),
                uri: reference.uri().to_owned(),
                certificate_der: reference.certificate_der().map(<[u8]>::to_vec),
            });
        }
        if let Some(reference) = status.identifier_list_ref() {
            has_unsupported_status_extension |= !reference.extensions().is_empty();
            status_references.push(VerifiedMdocStatusReference::IdentifierList {
                identifier: reference.identifier().to_vec(),
                uri: reference.uri().to_owned(),
                certificate_der: reference.certificate_der().map(<[u8]>::to_vec),
            });
        }
    }

    Ok(VerifiedMdocPresentation {
        document_count: documents.len(),
        document_types: documents
            .iter()
            .map(|document| verified_mdoc_type(document).to_owned())
            .collect(),
        disclosed_claims,
        status_references,
        has_unsupported_status_extension,
    })
}

fn verified_mdoc_documents(verified: &VerifiedMdocDeviceResponse) -> &[VerifiedMdoc] {
    verified.verified_documents()
}

fn verified_mdoc_namespaces(verified: &VerifiedMdoc) -> Option<&IssuerNameSpaces> {
    verified.namespaces()
}

fn verified_mdoc_type(verified: &VerifiedMdoc) -> &str {
    verified.doc_type()
}

fn map_mdoc_envelope_error(error: MdocEnvelopeError) -> MdocFormatError {
    // SSI 0.3 makes this upstream enum non-exhaustive. Keep the fallback now
    // so future upstream reasons fail closed without widening this API.
    #[allow(unreachable_patterns)]
    let reason = match error {
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::DocTypeMismatch) => {
            MdocFormatErrorReason::DocumentTypeMismatch
        }
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidSessionTranscript) => {
            MdocFormatErrorReason::SessionTranscriptMismatch
        }
        MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceAuthentication)
        | MdocEnvelopeError::InvalidInput(MdocInvalidInputReason::InvalidDeviceNameSpaces) => {
            MdocFormatErrorReason::InvalidDeviceAuthentication
        }
        MdocEnvelopeError::InvalidInput(
            MdocInvalidInputReason::MalformedDeviceResponse
            | MdocInvalidInputReason::UnsupportedDeviceResponseVersion
            | MdocInvalidInputReason::InvalidDeviceResponseStatus,
        )
        | MdocEnvelopeError::Cbor => MdocFormatErrorReason::InvalidDeviceResponse,
        MdocEnvelopeError::InvalidInput(_) => MdocFormatErrorReason::InvalidIssuerAuthentication,
        MdocEnvelopeError::InvalidSignature | MdocEnvelopeError::InvalidDigest => {
            MdocFormatErrorReason::InvalidIssuerAuthentication
        }
        MdocEnvelopeError::InvalidDeviceSignature => {
            MdocFormatErrorReason::InvalidDeviceAuthentication
        }
        MdocEnvelopeError::Expired => MdocFormatErrorReason::Expired,
        MdocEnvelopeError::UnsupportedOperation => MdocFormatErrorReason::UnsupportedOperation,
        MdocEnvelopeError::Signing => MdocFormatErrorReason::InvalidIssuerAuthentication,
        _ => MdocFormatErrorReason::InvalidIssuerAuthentication,
    };
    MdocFormatError::new(reason)
}

#[cfg(test)]
#[path = "mdoc_tests.rs"]
mod tests;
