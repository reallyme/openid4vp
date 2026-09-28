// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::jcs::canonicalize_json_text;
use reallyme_openid4vp_types::REQUEST_OBJECT_MEDIA_TYPE;
use reallyme_openid4vp_verifier::CompactJwt;
use zeroize::Zeroizing;

use crate::compare_secret::constant_time_str_eq;
use crate::define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
use crate::parse_form_urlencoded::{optional_unique_field, parse_form_urlencoded};
use crate::{RuntimeError, RuntimeErrorReason};

const FORM_URLENCODED_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const NO_STORE_CACHE_CONTROL: &str = "no-store";
const WALLET_NONCE_FIELD: &str = "wallet_nonce";
const WALLET_METADATA_FIELD: &str = "wallet_metadata";
const MAX_REQUEST_OBJECT_POST_BODY_BYTES: usize = 16 * 1024;
const MAX_WALLET_NONCE_BYTES: usize = 4 * 1024;
const MAX_WALLET_METADATA_BYTES: usize = 12 * 1024;

pub(crate) enum RequestObjectRetrieval {
    Get,
    Post {
        wallet_nonce: Option<Zeroizing<String>>,
        wallet_metadata: Option<Zeroizing<String>>,
    },
}

impl RequestObjectRetrieval {
    pub(crate) fn wallet_nonce(&self) -> Option<&str> {
        match self {
            Self::Get => None,
            Self::Post { wallet_nonce, .. } => wallet_nonce.as_deref().map(String::as_str),
        }
    }

    pub(crate) fn wallet_metadata(&self) -> Option<&str> {
        match self {
            Self::Get => None,
            Self::Post {
                wallet_metadata, ..
            } => wallet_metadata.as_deref().map(String::as_str),
        }
    }
}

/// Serve a hosted RFC 9101 Request Object for OpenID4VP `request_uri`.
pub fn serve_request_object_http(
    request: &RuntimeHttpRequest,
    request_object_jwt: &CompactJwt,
    expected_wallet_nonce: Option<&str>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let retrieval = parse_request_object_retrieval(request)?;
    match (retrieval.wallet_nonce(), expected_wallet_nonce) {
        (None, None) => {}
        (Some(actual), Some(expected)) => {
            if !constant_time_str_eq(actual, expected) {
                return Err(RuntimeError::new(RuntimeErrorReason::WalletNonceMismatch));
            }
        }
        (None, Some(_)) | (Some(_), None) => {
            return Err(RuntimeError::new(RuntimeErrorReason::WalletNonceMismatch));
        }
    }
    request_object_http_response(request_object_jwt)
}

pub(crate) fn parse_request_object_retrieval(
    request: &RuntimeHttpRequest,
) -> Result<RequestObjectRetrieval, RuntimeError> {
    validate_accept_header(request.accept.as_deref(), REQUEST_OBJECT_MEDIA_TYPE)?;
    match request.method {
        RuntimeHttpMethod::Get => {
            if !request.body.is_empty() {
                return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
            }
            Ok(RequestObjectRetrieval::Get)
        }
        RuntimeHttpMethod::Post => {
            if request.body.len() > MAX_REQUEST_OBJECT_POST_BODY_BYTES {
                return Err(RuntimeError::new(RuntimeErrorReason::BodyTooLarge));
            }
            validate_content_type(request.content_type.as_deref(), FORM_URLENCODED_MEDIA_TYPE)?;
            let pairs = parse_form_urlencoded(&request.body)?;
            // OpenID4VP requires request_uri POST endpoints to ignore
            // unrecognized parameters. The decoder enforces global body,
            // pair, key, and value bounds before known fields are selected.
            let wallet_nonce = optional_unique_field(&pairs, WALLET_NONCE_FIELD)?
                .map(validate_wallet_nonce)
                .transpose()?;
            let wallet_metadata = optional_unique_field(&pairs, WALLET_METADATA_FIELD)?
                .map(validate_wallet_metadata)
                .transpose()?;
            Ok(RequestObjectRetrieval::Post {
                wallet_nonce,
                wallet_metadata,
            })
        }
    }
}

fn validate_wallet_nonce(value: &str) -> Result<Zeroizing<String>, RuntimeError> {
    if value.is_empty() || value.len() > MAX_WALLET_NONCE_BYTES {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    Ok(Zeroizing::new(value.to_owned()))
}

fn validate_wallet_metadata(value: &str) -> Result<Zeroizing<String>, RuntimeError> {
    if value.is_empty() || value.len() > MAX_WALLET_METADATA_BYTES {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    let canonical = Zeroizing::new(
        canonicalize_json_text(value)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))?,
    );
    if canonical.len() > MAX_WALLET_METADATA_BYTES {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    // JCS output has no leading whitespace, so the first byte identifies the
    // JSON top-level kind without materializing a second, non-zeroizing tree.
    if canonical.as_bytes().first() != Some(&b'{') {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    Ok(canonical)
}

pub(crate) fn request_object_http_response(
    request_object_jwt: &CompactJwt,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    Ok(RuntimeHttpResponse::with_body(
        200,
        REQUEST_OBJECT_MEDIA_TYPE,
        request_object_jwt.as_str().as_bytes().to_vec(),
    )
    .with_cache_control(NO_STORE_CACHE_CONTROL)
    .accepted())
}

pub(crate) fn validate_content_type(
    actual: Option<&str>,
    expected: &str,
) -> Result<(), RuntimeError> {
    let Some(actual) = actual else {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidContentType));
    };
    let media_type = match actual.split(';').next() {
        Some(value) => value.trim(),
        None => "",
    };
    if media_type.eq_ignore_ascii_case(expected) {
        return Ok(());
    }
    Err(RuntimeError::new(RuntimeErrorReason::InvalidContentType))
}

pub(crate) fn validate_accept_header(
    actual: Option<&str>,
    produced: &str,
) -> Result<(), RuntimeError> {
    let Some(actual) = actual else {
        return Ok(());
    };
    for item in actual.split(',') {
        let media_range = match item.split(';').next() {
            Some(value) => value.trim(),
            None => "",
        };
        if media_range == "*/*" || media_range == "application/*" {
            return Ok(());
        }
        if media_range.eq_ignore_ascii_case(produced) {
            return Ok(());
        }
    }
    Err(RuntimeError::new(RuntimeErrorReason::InvalidAcceptHeader))
}

pub(crate) const fn form_urlencoded_media_type() -> &'static str {
    FORM_URLENCODED_MEDIA_TYPE
}
