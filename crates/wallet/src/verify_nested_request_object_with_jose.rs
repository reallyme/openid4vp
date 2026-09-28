// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::classify_request_object_jwt;
use zeroize::Zeroizing;

use crate::{
    RequestObjectSignatureVerifier, VerifiedRequestObject, WalletError, WalletErrorReason,
};

const DEFAULT_MAX_NESTED_REQUEST_OBJECT_BYTES: usize = 64 * 1024;

/// `reallyme-jose` backed verifier for encrypted nested RFC 9101 Request Objects.
///
/// RFC 9101 Section 10.1 requires Request Objects using both signature and
/// encryption to be signed first, then encrypted. This adapter decrypts the
/// outer compact JWE, validates that the plaintext is a compact signed Request
/// Object, and then delegates signature verification to the injected inner
/// verifier.
pub struct JoseNestedRequestObjectVerifier<D, V> {
    decryptor: D,
    inner_verifier: V,
    policy: reallyme_jose::jwe::CompactJwePolicy<'static>,
    max_plaintext_jwt_bytes: usize,
}

impl<D, V> JoseNestedRequestObjectVerifier<D, V> {
    /// Build a verifier with OpenID4VP nested Request Object defaults.
    pub fn new(decryptor: D, inner_verifier: V) -> Self {
        Self {
            decryptor,
            inner_verifier,
            policy: reallyme_jose::jwe::CompactJwePolicy::openid4vp_direct_post_jwt(),
            max_plaintext_jwt_bytes: DEFAULT_MAX_NESTED_REQUEST_OBJECT_BYTES,
        }
    }

    /// Build a verifier with explicit JWE policy and plaintext size bound.
    pub const fn with_policy(
        decryptor: D,
        inner_verifier: V,
        policy: reallyme_jose::jwe::CompactJwePolicy<'static>,
        max_plaintext_jwt_bytes: usize,
    ) -> Self {
        Self {
            decryptor,
            inner_verifier,
            policy,
            max_plaintext_jwt_bytes,
        }
    }
}

impl<D, V> RequestObjectSignatureVerifier for JoseNestedRequestObjectVerifier<D, V>
where
    D: reallyme_jose::jwe::JweContentEncryptionKeyResolver + Send + Sync,
    V: RequestObjectSignatureVerifier,
{
    fn verify_request_object(
        &self,
        jwt: &str,
        invocation: &crate::WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        let plaintext = self.decrypt_inner_signed_jwt(jwt)?;
        let signed_jwt = nested_signed_jwt(plaintext.as_slice(), self.max_plaintext_jwt_bytes)?;
        self.inner_verifier
            .verify_request_object(signed_jwt, invocation, now_unix)
    }
}

impl<D, V> JoseNestedRequestObjectVerifier<D, V>
where
    D: reallyme_jose::jwe::JweContentEncryptionKeyResolver,
{
    fn decrypt_inner_signed_jwt(&self, jwt: &str) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        reallyme_jose::jwe::decrypt_compact_jwe_bytes(jwt, &self.policy, &self.decryptor)
            .map_err(map_jwe_verification_error)
    }
}

fn map_jwe_verification_error(error: reallyme_jose::jwe::JweError) -> WalletError {
    use reallyme_jose::jwe::JweError;

    let reason = match error {
        JweError::InputTooLarge | JweError::LengthOverflow => {
            WalletErrorReason::RequestObjectTooLarge
        }
        JweError::UnsupportedKeyManagementAlgorithm
        | JweError::UnsupportedContentEncryptionAlgorithm => {
            WalletErrorReason::UnsupportedRequestObjectAlgorithm
        }
        JweError::InvalidCompact
        | JweError::InvalidEncoding
        | JweError::InvalidHeader
        | JweError::MissingRequiredHeaderParameter
        | JweError::HeaderPolicyMismatch
        | JweError::KidPolicyMismatch
        | JweError::TypPolicyMismatch
        | JweError::CtyPolicyMismatch
        | JweError::ApuPolicyMismatch
        | JweError::ApvPolicyMismatch
        | JweError::InvalidEncryptedKey
        | JweError::InvalidContentEncryptionKey
        | JweError::InvalidContentCipherInput
        | JweError::Decrypt
        | JweError::Encrypt
        | JweError::InvalidKeyAgreementKey
        | JweError::InvalidSharedSecret
        | JweError::KeyDerivation
        | JweError::Randomness
        | JweError::InvalidPayloadJson => WalletErrorReason::InvalidRequestObject,
        _ => WalletErrorReason::InvalidRequestObject,
    };
    WalletError::new(reason)
}

fn nested_signed_jwt(
    plaintext: &[u8],
    max_plaintext_jwt_bytes: usize,
) -> Result<&str, WalletError> {
    if plaintext.len() > max_plaintext_jwt_bytes {
        return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
    }
    let signed_jwt = core::str::from_utf8(plaintext)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    let kind = classify_request_object_jwt(signed_jwt)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    if kind != reallyme_openid4vp_types::RequestObjectJwtKind::Signed {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    Ok(signed_jwt)
}

#[cfg(test)]
#[path = "verify_nested_request_object_with_jose_tests.rs"]
mod tests;
