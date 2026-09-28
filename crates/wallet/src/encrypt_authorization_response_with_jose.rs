// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_codec::base64url::base64url_to_bytes;
use reallyme_codec::jcs::canonicalize_trusted_json_value;
use reallyme_jose::jwe::{
    encrypt_compact_jwe_bytes, CompactJweEncryptRequest, JweContentEncryptionAlgorithm,
    P256EcdhEsJweKeyEncryptor,
};
use reallyme_openid4vp_types::{
    canonical_authorization_response_bytes, AuthorizationRequestObject, AuthorizationResponse,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{WalletAuthorizationRequest, WalletError, WalletErrorReason};

const MAX_ENCRYPTION_KEYS: usize = 16;
const P256_COORDINATE_BYTES: usize = 32;
const P256_UNCOMPRESSED_PUBLIC_KEY_BYTES: usize = 65;
const P256_COORDINATE_BASE64URL_BYTES: usize = 43;
const MAX_KEY_ID_BYTES: usize = 256;
const MAX_CONTENT_ENCRYPTION_ALGORITHMS: usize = 8;

/// Encrypt an OpenID4VP Authorization Response under verifier metadata.
///
/// Key selection skips unrelated or malformed JWKs, as required when a JWKS
/// contains multiple purposes, but fails closed if no usable P-256 ECDH-ES key
/// remains. The protected header carries the selected `kid` and `cty=json`.
pub fn encrypt_authorization_response_with_jose(
    verified_request: &impl WalletAuthorizationRequest,
    response: &AuthorizationResponse,
) -> Result<String, WalletError> {
    let request = verified_request.request();
    let metadata = response_encryption_metadata(request)?;
    let mut selected = select_response_encryption_key(metadata)?;
    let enc = select_content_encryption_algorithm(
        metadata.get("encrypted_response_enc_values_supported"),
    )?;
    let plaintext =
        canonical_authorization_response_bytes(response).map_err(|_| encryption_failed())?;
    let encryption_request = CompactJweEncryptRequest::new(&plaintext, enc)
        .with_kid(selected.kid.as_str())
        .with_cty("json");
    let mut key_encryptor = P256EcdhEsJweKeyEncryptor::new(&selected.public_key_sec1);
    let mut random = reallyme_crypto::csprng::OsSecureRandom;
    let result = encrypt_compact_jwe_bytes(&encryption_request, &mut key_encryptor, &mut random)
        .map_err(|_| encryption_failed());
    selected.zeroize();
    result
}

/// Return the raw RFC 7638 SHA-256 thumbprint of the encryption JWK that the
/// wallet will use for this request.
///
/// ISO mdoc handover construction and response JWE encryption must select the
/// same verifier key. Keeping selection in this module prevents a caller from
/// committing one key to `SessionTranscript` and encrypting the response to a
/// different key when a JWKS contains multiple entries.
pub fn response_encryption_key_thumbprint_sha256(
    verified_request: &impl WalletAuthorizationRequest,
) -> Result<[u8; 32], WalletError> {
    let request = verified_request.request();
    let metadata = response_encryption_metadata(request)?;
    let mut selected = select_response_encryption_key(metadata)?;
    let result = selected.thumbprint_sha256();
    selected.zeroize();
    result
}

fn response_encryption_metadata(
    request: &AuthorizationRequestObject,
) -> Result<&Map<String, Value>, WalletError> {
    request
        .client_metadata
        .as_ref()
        .and_then(|metadata| metadata.raw.as_object())
        .ok_or_else(missing_metadata)
}

fn select_response_encryption_key(
    metadata: &Map<String, Value>,
) -> Result<UsableP256EncryptionKey, WalletError> {
    let keys = metadata
        .get("jwks")
        .and_then(Value::as_object)
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Value::as_array)
        .ok_or_else(missing_metadata)?;
    if keys.is_empty() || keys.len() > MAX_ENCRYPTION_KEYS {
        return Err(missing_metadata());
    }
    keys.iter()
        .find_map(|candidate| UsableP256EncryptionKey::try_from(candidate).ok())
        .ok_or_else(invalid_key)
}

struct UsableP256EncryptionKey {
    public_key_sec1: Vec<u8>,
    kid: String,
    x_encoded: String,
    y_encoded: String,
}

impl Zeroize for UsableP256EncryptionKey {
    fn zeroize(&mut self) {
        self.public_key_sec1.zeroize();
        self.kid.zeroize();
        self.x_encoded.zeroize();
        self.y_encoded.zeroize();
    }
}

impl Drop for UsableP256EncryptionKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl TryFrom<&Value> for UsableP256EncryptionKey {
    type Error = WalletError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let value = value.as_object().ok_or_else(invalid_key)?;
        if string_member(value, "kty") != Some("EC")
            || string_member(value, "crv") != Some("P-256")
            || string_member(value, "alg") != Some("ECDH-ES")
            || value
                .get("use")
                .is_some_and(|use_| use_.as_str() != Some("enc"))
            || value.contains_key("d")
        {
            return Err(invalid_key());
        }
        let kid = string_member(value, "kid").filter(|kid| {
            !kid.is_empty() && kid.len() <= MAX_KEY_ID_BYTES && !kid.chars().any(char::is_control)
        });
        let Some(kid) = kid else {
            return Err(invalid_key());
        };
        let x_encoded = bounded_coordinate(value, "x")?;
        let y_encoded = bounded_coordinate(value, "y")?;
        let mut x = base64url_to_bytes(x_encoded).map_err(|_| invalid_key())?;
        let mut y = base64url_to_bytes(y_encoded).map_err(|_| invalid_key())?;
        if x.len() != P256_COORDINATE_BYTES || y.len() != P256_COORDINATE_BYTES {
            x.zeroize();
            y.zeroize();
            return Err(invalid_key());
        }
        let mut public_key_sec1 = Vec::with_capacity(P256_UNCOMPRESSED_PUBLIC_KEY_BYTES);
        public_key_sec1.push(0x04);
        public_key_sec1.append(&mut x);
        public_key_sec1.append(&mut y);
        reallyme_crypto::p256::compress_public_key(&public_key_sec1).map_err(|_| invalid_key())?;
        Ok(Self {
            public_key_sec1,
            kid: kid.to_owned(),
            x_encoded: x_encoded.to_owned(),
            y_encoded: y_encoded.to_owned(),
        })
    }
}

impl UsableP256EncryptionKey {
    fn thumbprint_sha256(&self) -> Result<[u8; 32], WalletError> {
        // RFC 7638 hashes only the required public members. JCS fixes member
        // ordering and escaping independently of serde_json map configuration.
        let mut public_members = Map::new();
        public_members.insert("crv".to_owned(), Value::String("P-256".to_owned()));
        public_members.insert("kty".to_owned(), Value::String("EC".to_owned()));
        public_members.insert("x".to_owned(), Value::String(self.x_encoded.clone()));
        public_members.insert("y".to_owned(), Value::String(self.y_encoded.clone()));
        let mut canonical = canonicalize_trusted_json_value(&Value::Object(public_members))
            .map_err(|_| invalid_key())?;
        let digest: [u8; 32] = Sha256::digest(canonical.as_bytes()).into();
        canonical.zeroize();
        Ok(digest)
    }
}

fn select_content_encryption_algorithm(
    advertised: Option<&Value>,
) -> Result<JweContentEncryptionAlgorithm, WalletError> {
    let Some(advertised) = advertised else {
        return Ok(JweContentEncryptionAlgorithm::A128Gcm);
    };
    let values = advertised.as_array().ok_or_else(unsupported_algorithm)?;
    if values.is_empty() || values.len() > MAX_CONTENT_ENCRYPTION_ALGORITHMS {
        return Err(unsupported_algorithm());
    }
    let mut supports_a128_gcm = false;
    for value in values {
        match value.as_str() {
            Some("A256GCM") => return Ok(JweContentEncryptionAlgorithm::A256Gcm),
            Some("A128GCM") => supports_a128_gcm = true,
            Some(_) => {}
            None => return Err(unsupported_algorithm()),
        }
    }
    if supports_a128_gcm {
        Ok(JweContentEncryptionAlgorithm::A128Gcm)
    } else {
        Err(unsupported_algorithm())
    }
}

fn string_member<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

fn bounded_coordinate<'a>(
    object: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, WalletError> {
    let encoded = string_member(object, name).ok_or_else(invalid_key)?;
    if encoded.len() != P256_COORDINATE_BASE64URL_BYTES {
        return Err(invalid_key());
    }
    Ok(encoded)
}

const fn missing_metadata() -> WalletError {
    WalletError::new(WalletErrorReason::MissingResponseEncryptionMetadata)
}

const fn unsupported_algorithm() -> WalletError {
    WalletError::new(WalletErrorReason::UnsupportedResponseEncryptionAlgorithm)
}

const fn invalid_key() -> WalletError {
    WalletError::new(WalletErrorReason::InvalidResponseEncryptionKey)
}

const fn encryption_failed() -> WalletError {
    WalletError::new(WalletErrorReason::ResponseEncryptionFailed)
}

#[cfg(test)]
#[path = "encrypt_authorization_response_with_jose_tests.rs"]
mod tests;
