// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict, bounded parsing for untrusted Request Object protected headers.

use core::fmt;
use std::collections::BTreeSet;

use serde::de::{MapAccess, Visitor};
use serde::Deserializer;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{BoundedX509CertificateChain, WalletError, WalletErrorReason};

pub(super) const MAX_SIGNED_REQUEST_OBJECT_BYTES: usize = 64 * 1024;
// ceil(16 KiB / 3) * 4. Checking the encoded form before decoding prevents an
// attacker-controlled `x5c` string from allocating beyond the DER policy cap.
pub(super) const MAX_X509_CERTIFICATE_BASE64_BYTES: usize = 21_848;

pub(super) struct EmbeddedKeyHeader {
    pub(super) has_jwk: bool,
    pub(super) x509_chain: Option<BoundedX509CertificateChain>,
}

/// Zeroizing owner for untrusted protected-header JSON.
///
/// RFC 7515 Section 4.1.6 permits certificate material in `x5c`. Retaining a
/// generic JSON tree is useful for strict duplicate-member detection, but its
/// strings must not survive an early return in ordinary allocator memory.
struct SensitiveHeaderObject(serde_json::Map<String, serde_json::Value>);

impl SensitiveHeaderObject {
    fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.0.get(key)
    }
}

impl zeroize::Zeroize for SensitiveHeaderObject {
    fn zeroize(&mut self) {
        zeroize_json_object(&mut self.0);
    }
}

impl Drop for SensitiveHeaderObject {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl ZeroizeOnDrop for SensitiveHeaderObject {}

pub(super) fn validate_compact_jws_envelope(jwt: &str) -> Result<(), WalletError> {
    if jwt.len() > MAX_SIGNED_REQUEST_OBJECT_BYTES {
        return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
    }

    // RFC 7515 Section 3.1 defines compact JWS as exactly three non-empty
    // base64url segments. Enforce this before invoking any trust resolver so
    // malformed attacker input cannot trigger certificate or key lookups.
    let mut segments = jwt.split('.');
    let header = segments.next();
    let payload = segments.next();
    let signature = segments.next();
    let has_extra_segment = segments.next().is_some();
    if has_extra_segment
        || header.is_none_or(str::is_empty)
        || payload.is_none_or(str::is_empty)
        || signature.is_none_or(str::is_empty)
    {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    Ok(())
}

pub(super) fn parse_embedded_key_header(jwt: &str) -> Result<EmbeddedKeyHeader, WalletError> {
    let mut segments = jwt.split('.');
    let encoded_header = segments
        .next()
        .ok_or_else(|| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    let header_bytes = Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(encoded_header)
            .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?,
    );
    let header = parse_strict_header_object(header_bytes.as_slice())?;
    let has_jwk = header.contains_key("jwk");
    let x509_chain = match header.get("x5c") {
        Some(value) => {
            let entries = value.as_array().ok_or_else(|| {
                WalletError::new(WalletErrorReason::MalformedX509CertificateChain)
            })?;
            if entries.is_empty() || entries.len() > crate::MAX_X509_CHAIN_CERTIFICATES {
                return Err(WalletError::new(
                    WalletErrorReason::MalformedX509CertificateChain,
                ));
            }
            // A partially decoded chain may contain subject data even when a
            // later entry is malformed. Keep the temporary owner zeroizing so
            // every early-return path wipes already-decoded DER.
            let mut certificates_der = Zeroizing::new(Vec::with_capacity(entries.len()));
            for entry in entries {
                let encoded = entry.as_str().ok_or_else(|| {
                    WalletError::new(WalletErrorReason::MalformedX509CertificateChain)
                })?;
                if encoded.len() > MAX_X509_CERTIFICATE_BASE64_BYTES {
                    return Err(WalletError::new(
                        WalletErrorReason::MalformedX509CertificateChain,
                    ));
                }
                certificates_der.push(reallyme_codec::base64::base64_to_bytes(encoded).map_err(
                    |_| WalletError::new(WalletErrorReason::MalformedX509CertificateChain),
                )?);
            }
            let decoded_chain = core::mem::take(&mut *certificates_der);
            Some(BoundedX509CertificateChain::new(decoded_chain)?)
        }
        None => None,
    };
    Ok(EmbeddedKeyHeader {
        has_jwk,
        x509_chain,
    })
}

fn parse_strict_header_object(header_bytes: &[u8]) -> Result<SensitiveHeaderObject, WalletError> {
    struct HeaderObjectVisitor;

    impl<'de> Visitor<'de> for HeaderObjectVisitor {
        type Value = serde_json::Map<String, serde_json::Value>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JOSE protected header object without duplicate members")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = BTreeSet::new();
            let mut output = serde_json::Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key.clone()) {
                    return Err(serde::de::Error::custom("duplicate JOSE header member"));
                }
                let value = map.next_value::<serde_json::Value>()?;
                output.insert(key, value);
            }
            Ok(output)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(header_bytes);
    let header = deserializer
        .deserialize_map(HeaderObjectVisitor)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    deserializer
        .end()
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    Ok(SensitiveHeaderObject(header))
}

fn zeroize_json_object(object: &mut serde_json::Map<String, serde_json::Value>) {
    let owned = core::mem::take(object);
    for (mut key, mut value) in owned {
        zeroize::Zeroize::zeroize(&mut key);
        zeroize_json_value(&mut value);
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(string) => zeroize::Zeroize::zeroize(string),
        serde_json::Value::Array(values) => {
            for nested in values {
                zeroize_json_value(nested);
            }
        }
        serde_json::Value::Object(object) => zeroize_json_object(object),
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}
