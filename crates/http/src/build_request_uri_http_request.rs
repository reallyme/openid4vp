// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{HttpAdapterError, HttpAdapterErrorReason};

/// Content type for `request_uri_method=post` wallet nonce submissions.
pub const REQUEST_URI_POST_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

const WALLET_NONCE_FORM_KEY: &str = "wallet_nonce=";

/// HTTP request details needed to resolve an OpenID4VP `request_uri`.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestUriHttpRequest {
    /// Value to send in the HTTP `Accept` header.
    pub accept: &'static str,
    /// Value to send in the HTTP `Content-Type` header for POST requests.
    pub content_type: Option<&'static str>,
    /// Request body for POST requests.
    pub body: Vec<u8>,
}

impl fmt::Debug for RequestUriHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestUriHttpRequest")
            .field("accept", &self.accept)
            .field("content_type", &self.content_type)
            .field("body_byte_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

impl Zeroize for RequestUriHttpRequest {
    fn zeroize(&mut self) {
        self.body.zeroize();
    }
}

impl Drop for RequestUriHttpRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RequestUriHttpRequest {}

/// Build the HTTP headers/body for resolving a `request_uri` transport.
///
/// OpenID4VP keeps network I/O outside protocol crates. This helper gives
/// adapters one canonical place for the media type and wallet-generated
/// `wallet_nonce` form encoding required by the request_uri POST profile.
pub fn build_request_uri_http_request(
    method: RequestUriMethod,
    wallet_nonce: Option<&str>,
) -> Result<RequestUriHttpRequest, HttpAdapterError> {
    match method {
        RequestUriMethod::Get => Ok(RequestUriHttpRequest {
            accept: REQUEST_OBJECT_MEDIA_TYPE,
            content_type: None,
            body: Vec::new(),
        }),
        RequestUriMethod::Post => {
            let body = match wallet_nonce {
                None => Vec::new(),
                Some("") => {
                    return Err(HttpAdapterError::new(
                        HttpAdapterErrorReason::MissingWalletNonce,
                    ));
                }
                Some(nonce) => form_encode_wallet_nonce(nonce).into_bytes(),
            };
            Ok(RequestUriHttpRequest {
                accept: REQUEST_OBJECT_MEDIA_TYPE,
                content_type: Some(REQUEST_URI_POST_CONTENT_TYPE),
                body,
            })
        }
    }
}

fn form_encode_wallet_nonce(wallet_nonce: &str) -> String {
    let mut body = String::from(WALLET_NONCE_FORM_KEY);
    for byte in wallet_nonce.bytes() {
        if is_unreserved(byte) {
            body.push(char::from(byte));
            continue;
        }
        body.push('%');
        body.push(hex_char(byte >> 4));
        body.push(hex_char(byte & 0x0f));
    }
    body
}

const fn is_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

const fn hex_char(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'A' + (nibble - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
#[path = "build_request_uri_http_request_tests.rs"]
mod tests;
