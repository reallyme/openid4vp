// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;
use std::fmt;

use reallyme_openid4vp_types::{classify_request_object_jwt, RequestUriMethod};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WalletError, WalletErrorReason};

type RequestParameters = BTreeMap<String, String>;

/// Wallet authorization request transport classification.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthorizationRequestTransport {
    /// Request Object supplied by value through the `request` parameter.
    RequestJwt {
        /// Compact Request Object JWT.
        jwt: String,
        /// Expected client id supplied alongside `request`.
        expected_client_id: Option<String>,
        /// Wallet-generated nonce that the resolved Request Object must echo.
        expected_wallet_nonce: Option<String>,
    },
    /// Request Object supplied by reference through the `request_uri` parameter.
    RequestUri {
        /// URI to resolve outside the pure wallet parser.
        uri: String,
        /// Retrieval method.
        method: RequestUriMethod,
        /// Wallet nonce required for POST retrieval.
        wallet_nonce: Option<String>,
        /// Expected client id supplied alongside `request_uri`.
        expected_client_id: Option<String>,
    },
    /// Inline query parameters.
    InlineParams {
        /// Parsed query parameters.
        params: RequestParameters,
    },
}

impl fmt::Debug for AuthorizationRequestTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestJwt { jwt, .. } => formatter
                .debug_struct("RequestJwt")
                .field("jwt_byte_len", &jwt.len())
                .field("values", &"<redacted>")
                .finish(),
            Self::RequestUri { method, .. } => formatter
                .debug_struct("RequestUri")
                .field("method", method)
                .field("values", &"<redacted>")
                .finish(),
            Self::InlineParams { params } => formatter
                .debug_struct("InlineParams")
                .field("parameter_count", &params.len())
                .field("values", &"<redacted>")
                .finish(),
        }
    }
}

impl Zeroize for AuthorizationRequestTransport {
    fn zeroize(&mut self) {
        match self {
            Self::RequestJwt {
                jwt,
                expected_client_id,
                expected_wallet_nonce,
            } => {
                jwt.zeroize();
                expected_client_id.zeroize();
                expected_wallet_nonce.zeroize();
            }
            Self::RequestUri {
                uri,
                wallet_nonce,
                expected_client_id,
                ..
            } => {
                uri.zeroize();
                wallet_nonce.zeroize();
                expected_client_id.zeroize();
            }
            Self::InlineParams { params } => {
                let old = core::mem::take(params);
                for (mut key, mut value) in old {
                    key.zeroize();
                    value.zeroize();
                }
            }
        }
    }
}

impl Drop for AuthorizationRequestTransport {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestTransport {}

/// Policy for pure transport parsing and pre-verification size checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestTransportPolicy {
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Maximum accepted authorization request URI/query string length.
    pub max_authorization_request_bytes: usize,
    /// Maximum accepted authorization request parameter count.
    pub max_authorization_request_parameters: usize,
    /// Reject inline parameters when signed Request Objects are required.
    pub require_signed_request_object: bool,
}

impl Default for RequestTransportPolicy {
    fn default() -> Self {
        const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
        const DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES: usize = 16 * 1024;
        const DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS: usize = 64;
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            max_authorization_request_bytes: DEFAULT_MAX_AUTHORIZATION_REQUEST_BYTES,
            max_authorization_request_parameters: DEFAULT_MAX_AUTHORIZATION_REQUEST_PARAMETERS,
            require_signed_request_object: true,
        }
    }
}

/// Parse an OpenID4VP authorization request into a transport classification.
///
/// This ports the good meproto boundary: parsing is pure and network-free,
/// while `request_uri` resolution is delegated to transport adapters. The
/// parser accepts full URIs or raw query strings.
pub fn parse_authorization_request_transport(
    input: &str,
    policy: RequestTransportPolicy,
) -> Result<AuthorizationRequestTransport, WalletError> {
    let params = parse_input_to_params(input, policy)?;
    classify_transport(params, policy)
}

fn parse_input_to_params(
    input: &str,
    policy: RequestTransportPolicy,
) -> Result<RequestParameters, WalletError> {
    let trimmed = input.trim();
    if trimmed.len() > policy.max_authorization_request_bytes {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }
    let query = match trimmed.find('?') {
        Some(index) => {
            let Some(start) = index.checked_add(1) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            &trimmed[start..]
        }
        None => trimmed,
    };
    parse_querystring(query, policy.max_authorization_request_parameters)
}

fn parse_querystring(query: &str, max_parameters: usize) -> Result<RequestParameters, WalletError> {
    let mut out = BTreeMap::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if out.len() >= max_parameters {
            return Err(WalletError::new(
                WalletErrorReason::InvalidAuthorizationRequestTransport,
            ));
        }

        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;

        if !key.is_empty() && out.insert(key, value).is_some() {
            return Err(WalletError::new(
                WalletErrorReason::DuplicateAuthorizationRequestParameter,
            ));
        }
    }

    Ok(out)
}

fn percent_decode(input: &str) -> Result<String, WalletError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let Some(first_index) = index.checked_add(1) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            let Some(second_index) = index.checked_add(2) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            if second_index >= bytes.len() {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            }
            let Some(high) = hex_val(bytes[first_index]) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            let Some(low) = hex_val(bytes[second_index]) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            out.push((high << 4) | low);
            let Some(next_index) = index.checked_add(3) else {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidAuthorizationRequestTransport,
                ));
            };
            index = next_index;
            continue;
        }

        out.push(bytes[index]);
        let Some(next_index) = index.checked_add(1) else {
            return Err(WalletError::new(
                WalletErrorReason::InvalidAuthorizationRequestTransport,
            ));
        };
        index = next_index;
    }

    String::from_utf8(out)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidAuthorizationRequestTransport))
}

const fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(10 + (byte - b'a')),
        b'A'..=b'F' => Some(10 + (byte - b'A')),
        _ => None,
    }
}

fn classify_transport(
    params: RequestParameters,
    policy: RequestTransportPolicy,
) -> Result<AuthorizationRequestTransport, WalletError> {
    let expected_client_id = params
        .get("client_id")
        .filter(|value| !value.is_empty())
        .cloned();
    let request = params.get("request").cloned();
    let request_uri = params.get("request_uri").cloned();
    let wallet_nonce = params.get("wallet_nonce").cloned();

    if request.is_some() && request_uri.is_some() {
        return Err(WalletError::new(
            WalletErrorReason::ConflictingRequestObjectParameters,
        ));
    }

    if let Some(jwt) = request {
        validate_outer_parameter_names(&params, &["client_id", "request", "wallet_nonce"])?;
        if wallet_nonce.is_some() {
            return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
        }
        if jwt.len() > policy.max_request_jwt_bytes {
            return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
        }
        classify_request_object_jwt(&jwt)
            .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
        return Ok(AuthorizationRequestTransport::RequestJwt {
            jwt,
            expected_client_id,
            expected_wallet_nonce: None,
        });
    }

    if let Some(uri) = request_uri {
        validate_outer_parameter_names(
            &params,
            &[
                "client_id",
                "request_uri",
                "request_uri_method",
                "wallet_nonce",
            ],
        )?;
        let method =
            parse_request_uri_method(params.get("request_uri_method").map(String::as_str))?;
        if wallet_nonce.is_some() {
            return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
        }
        if method == RequestUriMethod::Post {
            return Ok(AuthorizationRequestTransport::RequestUri {
                uri,
                method,
                wallet_nonce: None,
                expected_client_id,
            });
        }

        return Ok(AuthorizationRequestTransport::RequestUri {
            uri,
            method,
            wallet_nonce: None,
            expected_client_id,
        });
    }

    if wallet_nonce.is_some() {
        return Err(WalletError::new(WalletErrorReason::UnexpectedWalletNonce));
    }

    if policy.require_signed_request_object {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }

    Ok(AuthorizationRequestTransport::InlineParams { params })
}

fn validate_outer_parameter_names(
    params: &RequestParameters,
    allowed: &[&str],
) -> Result<(), WalletError> {
    if params.keys().any(|name| !allowed.contains(&name.as_str())) {
        return Err(WalletError::new(
            WalletErrorReason::InvalidAuthorizationRequestTransport,
        ));
    }
    Ok(())
}

fn parse_request_uri_method(method: Option<&str>) -> Result<RequestUriMethod, WalletError> {
    match method {
        None | Some("get") => Ok(RequestUriMethod::Get),
        Some("post") => Ok(RequestUriMethod::Post),
        Some(_) => Err(WalletError::new(
            WalletErrorReason::UnsupportedRequestUriMethod,
        )),
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
