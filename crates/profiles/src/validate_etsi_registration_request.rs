// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structural TS 119 472-2 request checks before registration authentication.

use reallyme_openid4vp_types::{AuthorizationRequestObject, ClientIdentifierPrefix};
use serde_json::Value as JsonValue;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

const REGISTRAR_DATASET_FORMAT: &str = "registrar_dataset";
const REGISTRATION_CERT_FORMAT: &str = "registration_cert";
const MAX_REGISTRATION_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_REGISTRAR_IDENTIFIER_BYTES: usize = 512;
const MAX_REGISTRAR_URI_BYTES: usize = 2_048;

/// Stable reasons for a malformed EUDI relying-party request profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtsiRegistrationRequestErrorReason {
    /// The request does not use the required authenticated client scheme.
    InvalidClientIdentifier,
    /// Mandatory signed Request Object metadata is missing or malformed.
    InvalidRequestMetadata,
    /// Registrar-provided data is absent, ambiguous, or malformed.
    InvalidRegistrarDataset,
    /// The optional registration certificate encoding is malformed.
    InvalidRegistrationCertificate,
}

/// Profile failure without retaining requester data or backend text.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("invalid ETSI registration request profile")]
pub struct EtsiRegistrationRequestError {
    reason: EtsiRegistrationRequestErrorReason,
}

impl EtsiRegistrationRequestError {
    const fn new(reason: EtsiRegistrationRequestErrorReason) -> Self {
        Self { reason }
    }

    /// Return the fixed profile failure reason.
    pub const fn reason(self) -> EtsiRegistrationRequestErrorReason {
        self.reason
    }
}

/// Bounded, structurally checked evidence from one signed request.
///
/// The registrar dataset remains a request assertion. Neither its contents
/// nor the optional registration certificate are trusted until their own
/// signature, status, authority, and requester association are verified.
pub struct EtsiRegistrationRequest<'a> {
    registrar_dataset: &'a JsonValue,
    registrar_identifier: &'a str,
    registry_uri: &'a str,
    intended_use_identifier: &'a str,
    registration_certificate_b64url: Option<&'a str>,
}

impl<'a> EtsiRegistrationRequest<'a> {
    /// Borrow the registrar dataset for the separately authenticated lookup.
    #[must_use]
    pub const fn registrar_dataset(&self) -> &'a JsonValue {
        self.registrar_dataset
    }

    /// Return the request-asserted RP identifier for an authenticated lookup.
    #[must_use]
    pub const fn registrar_identifier(&self) -> &'a str {
        self.registrar_identifier
    }

    /// Return the request-asserted registrar URI, which is not a trust anchor.
    #[must_use]
    pub const fn registry_uri(&self) -> &'a str {
        self.registry_uri
    }

    /// Return the request-asserted intended-use identifier for lookup binding.
    #[must_use]
    pub const fn intended_use_identifier(&self) -> &'a str {
        self.intended_use_identifier
    }

    /// Borrow the optional encoded WRPRC for proof and status verification.
    #[must_use]
    pub const fn registration_certificate_b64url(&self) -> Option<&'a str> {
        self.registration_certificate_b64url
    }
}

/// Check the signed Authorization Request body required by TS 119 472-2.
///
/// This is deliberately a structural check. Callers must independently
/// authenticate the WRPAC request signer, registrar, WRPRC issuer, current
/// registration status, and association before authorizing disclosure.
pub fn validate_etsi_registration_request(
    request: &AuthorizationRequestObject,
) -> Result<EtsiRegistrationRequest<'_>, EtsiRegistrationRequestError> {
    if request
        .client_id
        .as_ref()
        .map(|client_id| client_id.prefix())
        != Some(ClientIdentifierPrefix::X509Hash)
    {
        return Err(EtsiRegistrationRequestError::new(
            EtsiRegistrationRequestErrorReason::InvalidClientIdentifier,
        ));
    }
    if request.aud.as_ref().is_none_or(Vec::is_empty)
        || !has_declared_response_encryption_key(request)
    {
        return Err(EtsiRegistrationRequestError::new(
            EtsiRegistrationRequestErrorReason::InvalidRequestMetadata,
        ));
    }
    let entries = request.verifier_info.as_ref().ok_or_else(|| {
        EtsiRegistrationRequestError::new(
            EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset,
        )
    })?;
    let mut registrar_dataset = None;
    let mut registration_certificate_b64url = None;
    for entry in entries {
        match entry.format() {
            REGISTRAR_DATASET_FORMAT => {
                if registrar_dataset.is_some()
                    || entry.credential_ids().is_some()
                    || !valid_registrar_dataset(entry.data())
                {
                    return Err(EtsiRegistrationRequestError::new(
                        EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset,
                    ));
                }
                registrar_dataset = Some(entry.data());
            }
            REGISTRATION_CERT_FORMAT => {
                let encoded = entry.data().as_str().ok_or_else(|| {
                    EtsiRegistrationRequestError::new(
                        EtsiRegistrationRequestErrorReason::InvalidRegistrationCertificate,
                    )
                })?;
                if registration_certificate_b64url.is_some()
                    || entry.credential_ids().is_some()
                    || !valid_registration_certificate_encoding(encoded)
                {
                    return Err(EtsiRegistrationRequestError::new(
                        EtsiRegistrationRequestErrorReason::InvalidRegistrationCertificate,
                    ));
                }
                registration_certificate_b64url = Some(encoded);
            }
            _ => {}
        }
    }
    let registrar_dataset = registrar_dataset.ok_or_else(registrar_dataset_error)?;
    let registrar_identifier = registrar_dataset
        .get("identifier")
        .and_then(JsonValue::as_str)
        .ok_or_else(registrar_dataset_error)?;
    let registry_uri = registrar_dataset
        .get("registryURI")
        .and_then(JsonValue::as_str)
        .ok_or_else(registrar_dataset_error)?;
    let intended_use_identifier = registrar_dataset
        .get("intendedUseIdentifier")
        .and_then(JsonValue::as_str)
        .ok_or_else(registrar_dataset_error)?;
    Ok(EtsiRegistrationRequest {
        registrar_dataset,
        registrar_identifier,
        registry_uri,
        intended_use_identifier,
        registration_certificate_b64url,
    })
}

const fn registrar_dataset_error() -> EtsiRegistrationRequestError {
    EtsiRegistrationRequestError::new(EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset)
}

fn has_declared_response_encryption_key(request: &AuthorizationRequestObject) -> bool {
    let Some(metadata) = request.client_metadata.as_ref() else {
        return false;
    };
    let Some(keys) = metadata
        .raw
        .get("jwks")
        .and_then(|jwks| jwks.get("keys"))
        .and_then(JsonValue::as_array)
    else {
        return false;
    };
    !keys.is_empty()
        && keys
            .iter()
            .all(|key| nonempty_member(key, "kid") && nonempty_member(key, "use"))
        && keys
            .iter()
            .any(|key| key.get("use").and_then(JsonValue::as_str) == Some("enc"))
        && keys.iter().enumerate().all(|(index, key)| {
            let Some(next_index) = index.checked_add(1) else {
                return false;
            };
            keys.iter()
                .skip(next_index)
                .all(|other| key.get("kid") != other.get("kid"))
        })
}

fn valid_registrar_dataset(data: &JsonValue) -> bool {
    data.as_object().is_some_and(|object| {
        !object.is_empty()
            && bounded_nonempty_member(data, "identifier", MAX_REGISTRAR_IDENTIFIER_BYTES)
            && data
                .get("registryURI")
                .and_then(JsonValue::as_str)
                .is_some_and(valid_https_uri)
            && bounded_nonempty_member(
                data,
                "intendedUseIdentifier",
                MAX_REGISTRAR_IDENTIFIER_BYTES,
            )
            && data
                .get("policyURI")
                .and_then(JsonValue::as_str)
                .is_some_and(valid_https_uri)
            && valid_localized_text_array(data.get("srvDescription"))
            && valid_localized_text_array(data.get("purpose"))
    })
}

fn valid_https_uri(value: &str) -> bool {
    value.len() <= MAX_REGISTRAR_URI_BYTES
        && Url::parse(value).is_ok_and(|uri| {
            uri.scheme() == "https"
                && uri.host_str().is_some()
                && uri.username().is_empty()
                && uri.password().is_none()
                && uri.fragment().is_none()
        })
}

fn bounded_nonempty_member(value: &JsonValue, member: &str, max_bytes: usize) -> bool {
    value
        .get(member)
        .and_then(JsonValue::as_str)
        .is_some_and(|text| !text.is_empty() && text.len() <= max_bytes)
}

fn nonempty_member(value: &JsonValue, member: &str) -> bool {
    value
        .get(member)
        .and_then(JsonValue::as_str)
        .is_some_and(|text| !text.is_empty())
}

fn valid_localized_text_array(value: Option<&JsonValue>) -> bool {
    value.and_then(JsonValue::as_array).is_some_and(|texts| {
        !texts.is_empty()
            && texts
                .iter()
                .all(|text| nonempty_member(text, "lang") && nonempty_member(text, "content"))
    })
}

fn valid_registration_certificate_encoding(encoded: &str) -> bool {
    if encoded.is_empty()
        || encoded.len() > MAX_REGISTRATION_CERTIFICATE_BYTES
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    let Ok(decoded) = reallyme_codec::base64url::base64url_to_bytes(encoded) else {
        return false;
    };
    let decoded = Zeroizing::new(decoded);
    !decoded.is_empty()
        && Zeroizing::new(reallyme_codec::base64url::bytes_to_base64url(&decoded)).as_str()
            == encoded
}

#[cfg(test)]
#[path = "validate_etsi_registration_request_tests.rs"]
mod tests;
