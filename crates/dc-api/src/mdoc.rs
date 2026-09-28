// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_codec::cbor::{encode_dag_cbor, CborValue};
use reallyme_openid4vp_types::ClientIdentifier;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{DcApiError, DcApiErrorReason};

/// Length of SHA-256 digests used by ISO/IEC 18013-7 Annex B handover inputs.
pub const SHA256_DIGEST_BYTES: usize = 32;
/// Maximum UTF-8 bytes accepted for one mdoc handover text parameter.
pub const MAX_MDOC_HANDOVER_TEXT_BYTES: usize = 8 * 1024;

const OPENID4VP_HANDOVER_LABEL: &str = "OpenID4VPHandover";
const OPENID4VP_DC_API_HANDOVER_LABEL: &str = "OpenID4VPDCAPIHandover";

/// Base64url encoded ISO 18013-5 `DeviceResponse` produced by `reallyme-mdoc`.
#[derive(Clone, PartialEq, Eq)]
pub struct MdocDeviceResponseB64(String);

impl MdocDeviceResponseB64 {
    /// Construct a non-empty base64url DeviceResponse wrapper.
    pub fn new(value: String) -> Result<Self, DcApiError> {
        if value.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::EmptyValue));
        }
        Ok(Self(value))
    }

    /// Return the encoded DeviceResponse value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MdocDeviceResponseB64 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MdocDeviceResponseB64")
            .field("byte_len", &self.0.len())
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for MdocDeviceResponseB64 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MdocDeviceResponseB64 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MdocDeviceResponseB64 {}

/// Handover variant used when constructing the ISO 18013-7 SessionTranscript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverKind {
    /// OpenID4VP redirect/direct_post handover.
    Redirect,
    /// OpenID4VP Digital Credentials API handover.
    DigitalCredentialsApi,
}

/// Redirect/direct_post handover input from OpenID4VP Annex B.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenId4VpRedirectHandover {
    /// Full final-spec client identifier.
    pub client_id: ClientIdentifier,
    /// Request nonce bound into mdoc device authentication.
    pub nonce: String,
    /// SHA-256 JWK thumbprint of the verifier response encryption key.
    pub jwk_thumbprint_sha256: Option<[u8; SHA256_DIGEST_BYTES]>,
    /// Response endpoint used in the OpenID4VP flow.
    pub response_uri: String,
}

impl fmt::Debug for OpenId4VpRedirectHandover {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpRedirectHandover")
            .field("client_id_prefix", &self.client_id.prefix())
            .field("has_jwk_thumbprint", &self.jwk_thumbprint_sha256.is_some())
            .field("has_response_uri", &!self.response_uri.is_empty())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for OpenId4VpRedirectHandover {
    fn zeroize(&mut self) {
        self.client_id.zeroize();
        self.nonce.zeroize();
        self.jwk_thumbprint_sha256.zeroize();
        self.response_uri.zeroize();
    }
}

impl Drop for OpenId4VpRedirectHandover {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OpenId4VpRedirectHandover {}

/// Digital Credentials API handover input from OpenID4VP Annex B.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenId4VpDcApiHandover {
    /// Browser origin invoking `navigator.credentials.get()`.
    pub origin: String,
    /// Request nonce bound into mdoc device authentication.
    pub nonce: String,
    /// SHA-256 JWK thumbprint for `dc_api.jwt`; absent for plain `dc_api`.
    pub jwk_thumbprint_sha256: Option<[u8; SHA256_DIGEST_BYTES]>,
}

impl fmt::Debug for OpenId4VpDcApiHandover {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenId4VpDcApiHandover")
            .field("has_jwk_thumbprint", &self.jwk_thumbprint_sha256.is_some())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for OpenId4VpDcApiHandover {
    fn zeroize(&mut self) {
        self.origin.zeroize();
        self.nonce.zeroize();
        self.jwk_thumbprint_sha256.zeroize();
    }
}

impl Drop for OpenId4VpDcApiHandover {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for OpenId4VpDcApiHandover {}

/// Union of handover inputs delegated to the mdoc CBOR encoder.
#[derive(Clone, PartialEq, Eq)]
pub enum HandoverDigestInput {
    /// Redirect/direct_post handover.
    Redirect(OpenId4VpRedirectHandover),
    /// Digital Credentials API handover.
    DigitalCredentialsApi(OpenId4VpDcApiHandover),
}

impl fmt::Debug for HandoverDigestInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Redirect(_) => HandoverKind::Redirect,
            Self::DigitalCredentialsApi(_) => HandoverKind::DigitalCredentialsApi,
        };
        formatter
            .debug_struct("HandoverDigestInput")
            .field("kind", &kind)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for HandoverDigestInput {
    fn zeroize(&mut self) {
        match self {
            Self::Redirect(value) => value.zeroize(),
            Self::DigitalCredentialsApi(value) => value.zeroize(),
        }
    }
}

impl Drop for HandoverDigestInput {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HandoverDigestInput {}

/// Encoded CBOR handover info produced by an mdoc-aware adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedHandoverInfo {
    bytes: Vec<u8>,
}

impl fmt::Debug for EncodedHandoverInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedHandoverInfo")
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for EncodedHandoverInfo {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EncodedHandoverInfo {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EncodedHandoverInfo {}

impl EncodedHandoverInfo {
    /// Construct non-empty encoded handover bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, DcApiError> {
        if bytes.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::HandoverEncodingFailed));
        }
        Ok(Self { bytes })
    }

    /// Return encoded handover bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Adapter boundary for OpenID4VP handover-info CBOR construction.
///
/// The canonical implementation in this crate is suitable for production.
/// The trait remains injectable so callers can independently verify the bytes
/// without coupling this protocol layer to ISO 18013-5 `DeviceResponse` types.
pub trait MdocHandoverCborEncoder: Send + Sync {
    /// Encode handover info as CBOR suitable for SessionTranscript construction.
    fn encode_handover_info(
        &self,
        input: &HandoverDigestInput,
    ) -> Result<EncodedHandoverInfo, DcApiError>;
}

/// Canonical encoder for the final OpenID4VP 1.0 Appendix B.2.6 structures.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalMdocHandoverCborEncoder;

impl MdocHandoverCborEncoder for CanonicalMdocHandoverCborEncoder {
    fn encode_handover_info(
        &self,
        input: &HandoverDigestInput,
    ) -> Result<EncodedHandoverInfo, DcApiError> {
        let value = match input {
            HandoverDigestInput::Redirect(input) => {
                let client_id = input.client_id.to_wire_value();
                validate_handover_text(&client_id)?;
                validate_handover_text(&input.nonce)?;
                validate_handover_text(&input.response_uri)?;
                CborValue::Array(vec![
                    CborValue::String(client_id),
                    CborValue::String(input.nonce.clone()),
                    optional_thumbprint_value(input.jwk_thumbprint_sha256),
                    CborValue::String(input.response_uri.clone()),
                ])
            }
            HandoverDigestInput::DigitalCredentialsApi(input) => {
                validate_handover_text(&input.origin)?;
                validate_handover_text(&input.nonce)?;
                CborValue::Array(vec![
                    CborValue::String(input.origin.clone()),
                    CborValue::String(input.nonce.clone()),
                    optional_thumbprint_value(input.jwk_thumbprint_sha256),
                ])
            }
        };
        let value = Zeroizing::new(value);
        let bytes = encode_dag_cbor(&value)
            .map_err(|_| DcApiError::new(DcApiErrorReason::HandoverEncodingFailed))?;
        EncodedHandoverInfo::new(bytes)
    }
}

/// SHA-256 digest of the encoded handover info.
#[derive(Clone, PartialEq, Eq)]
pub struct HandoverDigest {
    /// Handover variant.
    pub kind: HandoverKind,
    /// SHA-256 digest over the encoded handover info.
    pub digest: [u8; SHA256_DIGEST_BYTES],
}

impl fmt::Debug for HandoverDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandoverDigest")
            .field("kind", &self.kind)
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl Zeroize for HandoverDigest {
    fn zeroize(&mut self) {
        self.digest.zeroize();
    }
}

impl Drop for HandoverDigest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HandoverDigest {}

/// Canonically encoded ISO 18013-5 `SessionTranscript` for OpenID4VP.
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedMdocSessionTranscript {
    bytes: Vec<u8>,
}

impl EncodedMdocSessionTranscript {
    /// Return the canonical CBOR bytes used by mdoc device authentication.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedMdocSessionTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncodedMdocSessionTranscript")
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for EncodedMdocSessionTranscript {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for EncodedMdocSessionTranscript {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EncodedMdocSessionTranscript {}

/// Build the redirect/direct_post handover digest for an ISO mdoc response.
pub fn build_redirect_handover_digest(
    input: OpenId4VpRedirectHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    build_handover_digest(HandoverDigestInput::Redirect(input), encoder)
}

/// Build the Digital Credentials API handover digest for an ISO mdoc response.
pub fn build_dc_api_handover_digest(
    input: OpenId4VpDcApiHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    build_handover_digest(HandoverDigestInput::DigitalCredentialsApi(input), encoder)
}

/// Build the complete redirect/direct_post `SessionTranscript` CBOR value.
pub fn build_redirect_session_transcript(
    input: OpenId4VpRedirectHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<EncodedMdocSessionTranscript, DcApiError> {
    let digest = build_redirect_handover_digest(input, encoder)?;
    encode_session_transcript(OPENID4VP_HANDOVER_LABEL, &digest.digest)
}

/// Build the complete Digital Credentials API `SessionTranscript` CBOR value.
pub fn build_dc_api_session_transcript(
    input: OpenId4VpDcApiHandover,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<EncodedMdocSessionTranscript, DcApiError> {
    let digest = build_dc_api_handover_digest(input, encoder)?;
    encode_session_transcript(OPENID4VP_DC_API_HANDOVER_LABEL, &digest.digest)
}

fn build_handover_digest(
    input: HandoverDigestInput,
    encoder: &impl MdocHandoverCborEncoder,
) -> Result<HandoverDigest, DcApiError> {
    let encoded = encoder.encode_handover_info(&input)?;
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    let digest = hasher.finalize().into();
    let kind = match &input {
        HandoverDigestInput::Redirect(_) => HandoverKind::Redirect,
        HandoverDigestInput::DigitalCredentialsApi(_) => HandoverKind::DigitalCredentialsApi,
    };
    Ok(HandoverDigest { kind, digest })
}

fn optional_thumbprint_value(thumbprint: Option<[u8; SHA256_DIGEST_BYTES]>) -> CborValue {
    match thumbprint {
        Some(value) => CborValue::Bytes(value.to_vec()),
        None => CborValue::Null,
    }
}

fn validate_handover_text(value: &str) -> Result<(), DcApiError> {
    if value.is_empty() {
        return Err(DcApiError::new(DcApiErrorReason::EmptyValue));
    }
    if value.len() > MAX_MDOC_HANDOVER_TEXT_BYTES {
        return Err(DcApiError::new(DcApiErrorReason::HandoverValueTooLarge));
    }
    Ok(())
}

fn encode_session_transcript(
    label: &str,
    digest: &[u8; SHA256_DIGEST_BYTES],
) -> Result<EncodedMdocSessionTranscript, DcApiError> {
    let value = Zeroizing::new(CborValue::Array(vec![
        CborValue::Null,
        CborValue::Null,
        CborValue::Array(vec![
            CborValue::String(label.to_owned()),
            CborValue::Bytes(digest.to_vec()),
        ]),
    ]));
    let bytes = encode_dag_cbor(&value)
        .map_err(|_| DcApiError::new(DcApiErrorReason::HandoverEncodingFailed))?;
    Ok(EncodedMdocSessionTranscript { bytes })
}

#[cfg(test)]
#[path = "mdoc_tests.rs"]
mod tests;
