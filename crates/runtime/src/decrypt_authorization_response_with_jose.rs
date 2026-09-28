// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_jose::jwe::{
    decrypt_compact_jwe_json, CompactJwePolicy, CompactJweProtectedHeader,
    JweContentEncryptionKeyResolver, JweError,
};
use reallyme_openid4vp_types::AuthorizationResponse;

use crate::{
    AuthorizationResponseDecryptionContext, AuthorizationResponseJwtDecryptor, RuntimeError,
    RuntimeErrorReason,
};

/// Resolves JWE key material within the verifier-owned session namespace.
pub trait SessionBoundJweContentEncryptionKeyResolver: Send + Sync {
    /// Return a CEK only when the protected header is valid for this exact session.
    fn resolve_session_content_encryption_key(
        &self,
        context: AuthorizationResponseDecryptionContext<'_>,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, JweError>;
}

/// Direct-key resolver that explicitly scopes a CEK to one runtime context.
pub struct SessionBoundDirectJweKeyResolver<'a> {
    key: &'a [u8],
    expected_session_key: Option<&'a str>,
}

impl<'a> SessionBoundDirectJweKeyResolver<'a> {
    /// Construct a resolver for a platform operation with no hosted route key.
    pub const fn platform(key: &'a [u8]) -> Self {
        Self {
            key,
            expected_session_key: None,
        }
    }

    /// Construct a resolver bound to an exact hosted response route key.
    pub const fn direct_post(key: &'a [u8], session_key: &'a str) -> Self {
        Self {
            key,
            expected_session_key: Some(session_key),
        }
    }
}

impl SessionBoundJweContentEncryptionKeyResolver for SessionBoundDirectJweKeyResolver<'_> {
    fn resolve_session_content_encryption_key(
        &self,
        context: AuthorizationResponseDecryptionContext<'_>,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, JweError> {
        if context.direct_post_session_key() != self.expected_session_key {
            return Err(JweError::InvalidEncryptedKey);
        }
        reallyme_jose::jwe::DirectJweKeyResolver::new(self.key)
            .resolve_content_encryption_key(header, encrypted_key)
    }
}

struct ContextualResolver<'a, R> {
    inner: &'a R,
    context: AuthorizationResponseDecryptionContext<'a>,
}

impl<R> JweContentEncryptionKeyResolver for ContextualResolver<'_, R>
where
    R: SessionBoundJweContentEncryptionKeyResolver,
{
    fn resolve_content_encryption_key(
        &self,
        header: &CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, JweError> {
        self.inner
            .resolve_session_content_encryption_key(self.context, header, encrypted_key)
    }
}

/// `reallyme-jose` backed decryptor for OpenID4VP encrypted Authorization Responses.
///
/// The runtime still depends on the [`AuthorizationResponseJwtDecryptor`] trait
/// at service boundaries so SDKs and services can inject platform key storage.
/// This adapter is the production JOSE implementation for hosts that already
/// resolve a content-encryption key through `reallyme-jose`.
pub struct JoseAuthorizationResponseJwtDecryptor<R> {
    key_resolver: R,
    policy: CompactJwePolicy<'static>,
}

impl<R> JoseAuthorizationResponseJwtDecryptor<R> {
    /// Build a decryptor using the OpenID4VP `direct_post.jwt` JWE policy.
    pub fn new(key_resolver: R) -> Self {
        Self {
            key_resolver,
            policy: CompactJwePolicy::openid4vp_direct_post_jwt(),
        }
    }

    /// Build a decryptor with an explicit JOSE policy.
    ///
    /// This exists for HAIP, conformance, and service-host profiles that need
    /// stricter header constraints such as mandatory `kid` or expected `cty`.
    pub fn with_policy(key_resolver: R, policy: CompactJwePolicy<'static>) -> Self {
        Self {
            key_resolver,
            policy,
        }
    }
}

impl<R> AuthorizationResponseJwtDecryptor for JoseAuthorizationResponseJwtDecryptor<R>
where
    R: SessionBoundJweContentEncryptionKeyResolver,
{
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
        context: AuthorizationResponseDecryptionContext<'_>,
    ) -> Result<AuthorizationResponse, RuntimeError> {
        let resolver = ContextualResolver {
            inner: &self.key_resolver,
            context,
        };
        decrypt_compact_jwe_json(jwt, &self.policy, &resolver)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::ResponseJwtDecryptionFailed))
    }
}
