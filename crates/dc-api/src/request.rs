// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{AuthorizationRequestObject, ResponseMode};
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{DcApiError, DcApiErrorReason};

/// OpenID4VP protocol identifier prefix used in Digital Credentials API requests.
pub const OPENID4VP_PROTOCOL_PREFIX: &str = "openid4vp-v1-";
/// Maximum encoded JWS JSON General Serialization payload accepted by the model.
pub const MAX_JWS_JSON_GENERAL_BYTES: usize = 128 * 1024;
/// Maximum signatures accepted in one JWS JSON General Serialization value.
pub const MAX_JWS_JSON_SIGNATURES: usize = 16;
/// Maximum compact signed Request Object accepted by the browser binding.
pub const MAX_COMPACT_REQUEST_OBJECT_BYTES: usize = 64 * 1024;

/// One signature entry in RFC 7515 JWS JSON General Serialization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwsJsonSignature {
    /// Integrity-protected JOSE header, encoded as base64url without padding.
    pub protected: String,
    /// Signature bytes, encoded as base64url without padding.
    pub signature: String,
}

impl JwsJsonSignature {
    /// Construct a bounded signature entry.
    pub fn new(protected: String, signature: String) -> Result<Self, DcApiError> {
        if !is_base64url_segment(&protected) || !is_base64url_segment(&signature) {
            return Err(DcApiError::new(DcApiErrorReason::InvalidRequestObject));
        }
        Ok(Self {
            protected,
            signature,
        })
    }
}

impl fmt::Debug for JwsJsonSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JwsJsonSignature(<redacted>)")
    }
}

impl Zeroize for JwsJsonSignature {
    fn zeroize(&mut self) {
        self.protected.zeroize();
        self.signature.zeroize();
    }
}

impl Drop for JwsJsonSignature {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for JwsJsonSignature {}

/// RFC 7515 JWS JSON General Serialization used by multi-signed requests.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwsJsonGeneral {
    /// Shared Request Object claims payload, encoded as base64url without padding.
    pub payload: String,
    /// Independent protected-header and signature pairs over the shared payload.
    pub signatures: Vec<JwsJsonSignature>,
}

impl JwsJsonGeneral {
    /// Construct a bounded multi-signed Request Object.
    pub fn new(payload: String, signatures: Vec<JwsJsonSignature>) -> Result<Self, DcApiError> {
        let value = Self {
            payload,
            signatures,
        };
        value.validate()?;
        Ok(value)
    }

    /// Parse and validate a bounded JWS JSON General Serialization value.
    pub fn from_json(input: &[u8]) -> Result<Self, DcApiError> {
        if input.len() > MAX_JWS_JSON_GENERAL_BYTES {
            return Err(DcApiError::new(DcApiErrorReason::RequestObjectTooLarge));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(input);
        let value = Self::deserialize(&mut deserializer)
            .map_err(|_| DcApiError::new(DcApiErrorReason::InvalidRequestObject))?;
        deserializer
            .end()
            .map_err(|_| DcApiError::new(DcApiErrorReason::InvalidRequestObject))?;
        value.validate()?;
        Ok(value)
    }

    /// Revalidate bounds after crossing a construction or deserialization boundary.
    pub fn validate(&self) -> Result<(), DcApiError> {
        if !is_base64url_segment(&self.payload) || self.signatures.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::InvalidRequestObject));
        }
        if self.signatures.len() > MAX_JWS_JSON_SIGNATURES {
            return Err(DcApiError::new(
                DcApiErrorReason::TooManyRequestObjectSignatures,
            ));
        }
        if self.signatures.iter().any(|signature| {
            !is_base64url_segment(&signature.protected)
                || !is_base64url_segment(&signature.signature)
        }) {
            return Err(DcApiError::new(DcApiErrorReason::InvalidRequestObject));
        }
        let encoded_size =
            self.signatures
                .iter()
                .try_fold(self.payload.len(), |size, signature| {
                    size.checked_add(signature.protected.len())
                        .and_then(|value| value.checked_add(signature.signature.len()))
                });
        if encoded_size.is_none_or(|size| size > MAX_JWS_JSON_GENERAL_BYTES) {
            return Err(DcApiError::new(DcApiErrorReason::RequestObjectTooLarge));
        }
        Ok(())
    }
}

impl fmt::Debug for JwsJsonGeneral {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JwsJsonGeneral(<redacted>)")
    }
}

impl Zeroize for JwsJsonGeneral {
    fn zeroize(&mut self) {
        self.payload.zeroize();
        self.signatures.zeroize();
    }
}

impl Drop for JwsJsonGeneral {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for JwsJsonGeneral {}

/// OpenID4VP request kind encoded into the Digital Credentials API protocol id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DcApiRequestKind {
    /// Unsigned OpenID4VP request using `response_mode=dc_api`.
    Unsigned,
    /// Signed OpenID4VP Request Object using `response_mode=dc_api.jwt`.
    Signed,
    /// Multisigned request kind reserved by the OpenID4VP DC API appendix.
    Multisigned,
}

impl DcApiRequestKind {
    /// Return the protocol suffix.
    pub const fn as_suffix(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Signed => "signed",
            Self::Multisigned => "multisigned",
        }
    }
}

/// Digital Credentials API protocol identifier for OpenID4VP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcApiProtocol {
    /// OpenID4VP protocol version used by the W3C DC API binding.
    pub version: u8,
    /// Signedness and Request Object representation.
    pub kind: DcApiRequestKind,
}

impl DcApiProtocol {
    /// Construct the current OpenID4VP v1 protocol identifier.
    pub const fn v1(kind: DcApiRequestKind) -> Self {
        Self { version: 1, kind }
    }

    /// Return the protocol identifier string sent to the browser API.
    pub fn as_protocol_id(self) -> String {
        let mut protocol = OPENID4VP_PROTOCOL_PREFIX.to_owned();
        protocol.push_str(self.kind.as_suffix());
        protocol
    }
}

/// OpenID4VP request data carried in one Digital Credentials API entry.
#[derive(Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DigitalCredentialGetRequestData {
    /// Expanded unsigned OpenID4VP parameters.
    Unsigned(Box<AuthorizationRequestObject>),
    /// Compact Request Object JWS carried as `{"request": "<jwt>"}`.
    Signed {
        /// Compact Request Object JWT.
        request: String,
    },
    /// JWS JSON General Serialization carried as `{"request": { ... }}`.
    Multisigned {
        /// Multi-signed Request Object.
        request: JwsJsonGeneral,
    },
}

impl fmt::Debug for DigitalCredentialGetRequestData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(_) => formatter.write_str("Unsigned(<redacted>)"),
            Self::Signed { .. } => formatter.write_str("Signed(<redacted>)"),
            Self::Multisigned { .. } => formatter.write_str("Multisigned(<redacted>)"),
        }
    }
}

impl Zeroize for DigitalCredentialGetRequestData {
    fn zeroize(&mut self) {
        match self {
            Self::Unsigned(request) => request.zeroize(),
            Self::Signed { request } => request.zeroize(),
            Self::Multisigned { request } => request.zeroize(),
        }
    }
}

impl Drop for DigitalCredentialGetRequestData {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DigitalCredentialGetRequestData {}

/// One `DigitalCredentialGetRequest` entry for OpenID4VP.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DigitalCredentialGetRequest {
    /// Protocol identifier, such as `openid4vp-v1-signed`.
    pub protocol: String,
    /// OpenID4VP request data for the selected protocol.
    pub data: DigitalCredentialGetRequestData,
}

impl DigitalCredentialGetRequest {
    /// Build an unsigned OpenID4VP Digital Credentials API request entry.
    pub fn new(
        protocol: DcApiProtocol,
        mut data: AuthorizationRequestObject,
    ) -> Result<Self, DcApiError> {
        if protocol.version != 1 {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        normalize_dc_api_unsigned_request(protocol.kind, &mut data)?;
        Ok(Self {
            protocol: protocol.as_protocol_id(),
            data: DigitalCredentialGetRequestData::Unsigned(Box::new(data)),
        })
    }

    /// Revalidate protocol/data correspondence after crossing a boundary.
    pub fn validate(&self) -> Result<(), DcApiError> {
        match (self.protocol.as_str(), &self.data) {
            ("openid4vp-v1-unsigned", DigitalCredentialGetRequestData::Unsigned(data)) => {
                validate_dc_api_unsigned_request(DcApiRequestKind::Unsigned, data)
            }
            ("openid4vp-v1-signed", DigitalCredentialGetRequestData::Signed { request })
                if is_compact_jws(request) =>
            {
                Ok(())
            }
            (
                "openid4vp-v1-multisigned",
                DigitalCredentialGetRequestData::Multisigned { request },
            ) => request.validate(),
            _ => Err(DcApiError::new(DcApiErrorReason::InvalidProtocol)),
        }
    }

    /// Build a signed OpenID4VP Digital Credentials API request entry.
    pub fn new_signed_request_object(
        protocol: DcApiProtocol,
        request: String,
    ) -> Result<Self, DcApiError> {
        if protocol.version != 1 {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        if protocol.kind != DcApiRequestKind::Signed || !is_compact_jws(&request) {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        Ok(Self {
            protocol: protocol.as_protocol_id(),
            data: DigitalCredentialGetRequestData::Signed { request },
        })
    }

    /// Build a multi-signed OpenID4VP Digital Credentials API request entry.
    pub fn new_multisigned_request_object(
        protocol: DcApiProtocol,
        request: JwsJsonGeneral,
    ) -> Result<Self, DcApiError> {
        if protocol.version != 1 || protocol.kind != DcApiRequestKind::Multisigned {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
        Ok(Self {
            protocol: protocol.as_protocol_id(),
            data: DigitalCredentialGetRequestData::Multisigned { request },
        })
    }
}

fn is_base64url_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn is_compact_jws(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_COMPACT_REQUEST_OBJECT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return false;
    }
    let mut segments = value.split('.');
    let valid = segments.by_ref().take(3).all(is_base64url_segment);
    valid && segments.next().is_none() && value.split('.').count() == 3
}

pub(crate) fn unsigned_request_from_json_value(
    value: JsonValue,
) -> Result<AuthorizationRequestObject, serde_json::Error> {
    AuthorizationRequestObject::deserialize(value.into_deserializer())
}

pub(crate) fn general_jws_from_json_value(
    value: JsonValue,
) -> Result<JwsJsonGeneral, serde_json::Error> {
    JwsJsonGeneral::deserialize(value.into_deserializer())
}

fn validate_dc_api_unsigned_request(
    kind: DcApiRequestKind,
    data: &AuthorizationRequestObject,
) -> Result<(), DcApiError> {
    match kind {
        DcApiRequestKind::Unsigned => {
            if !matches!(
                data.response_mode,
                Some(ResponseMode::DcApi | ResponseMode::DcApiJwt)
            ) {
                return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
            }
            if data.response_uri.is_some()
                || data.redirect_uri.is_some()
                || data.wallet_nonce.is_some()
                || data.nonce.is_empty()
                || data.client_metadata_uri.is_some()
                || reallyme_openid4vp_dcql::validate_query(&data.dcql_query).is_err()
            {
                return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
            }
        }
        DcApiRequestKind::Signed | DcApiRequestKind::Multisigned => {
            return Err(DcApiError::new(DcApiErrorReason::InvalidProtocol));
        }
    }
    Ok(())
}

fn normalize_dc_api_unsigned_request(
    kind: DcApiRequestKind,
    data: &mut AuthorizationRequestObject,
) -> Result<(), DcApiError> {
    if kind == DcApiRequestKind::Unsigned {
        // Appendix A.2 requires these request members to be ignored. Removing
        // them at the boundary prevents later layers from accidentally using
        // attacker-controlled identity or origin values.
        data.client_id.zeroize();
        data.client_id = None;
        data.expected_origins.zeroize();
        data.expected_origins = None;
    }
    validate_dc_api_unsigned_request(kind, data)
}

/// Browser `CredentialRequestOptions.digital` payload.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DigitalCredentialRequestOptions {
    /// Non-empty set of protocol requests.
    pub requests: Vec<DigitalCredentialGetRequest>,
}

impl DigitalCredentialRequestOptions {
    /// Construct request options for the browser Digital Credentials API.
    pub fn new(requests: Vec<DigitalCredentialGetRequest>) -> Result<Self, DcApiError> {
        if requests.is_empty() {
            return Err(DcApiError::new(DcApiErrorReason::EmptyRequestSet));
        }
        for request in &requests {
            request.validate()?;
        }
        Ok(Self { requests })
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
