// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::AuthorizationResponse;

use crate::RuntimeError;

/// Host-provided key-selection context for an encrypted Authorization Response.
///
/// A hosted `direct_post.jwt` endpoint has an authenticated, one-time lookup
/// key in its route. Carrying that key into the decryptor prevents a malicious
/// response from selecting another live session's decryption key through an
/// attacker-controlled JOSE `kid`. Platform DC API adapters do not necessarily
/// have an equivalent route key and therefore use the unbound context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationResponseDecryptionContext<'a> {
    direct_post_session_key: Option<&'a str>,
}

impl<'a> AuthorizationResponseDecryptionContext<'a> {
    /// Bind decryption to the exact one-time hosted response route.
    #[must_use]
    pub const fn direct_post(session_key: &'a str) -> Self {
        Self {
            direct_post_session_key: Some(session_key),
        }
    }

    /// Construct an unbound platform context, such as a DC API operation.
    #[must_use]
    pub const fn platform() -> Self {
        Self {
            direct_post_session_key: None,
        }
    }

    /// Return the hosted session key when this is a direct-post operation.
    #[must_use]
    pub const fn direct_post_session_key(self) -> Option<&'a str> {
        self.direct_post_session_key
    }
}

/// Adapter boundary for encrypted OpenID4VP Authorization Responses.
///
/// Implementations are expected to decrypt an unsigned encrypted JWT/JWE,
/// enforce JOSE header policy (`alg`, `enc`, optional `kid`), and decode a
/// payload whose top-level members are the Authorization Response parameters.
/// Keeping this trait in the runtime layer lets ReallyMe Identity inject the
/// concrete `reallyme-crypto` backend without teaching protocol crates about
/// platform key storage.
pub trait AuthorizationResponseJwtDecryptor: Send + Sync {
    /// Decrypt a compact JWE Authorization Response.
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
        context: AuthorizationResponseDecryptionContext<'_>,
    ) -> Result<AuthorizationResponse, RuntimeError>;
}
