// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::AuthorizationRequestObject;
use secrecy::{ExposeSecret, SecretSlice};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WalletError, WalletErrorReason};

/// Wallet-trusted verifier attestation evidence extracted from the Request Object.
///
/// Signature verification, `typ=verifier-attestation+jwt`, `iss` trust,
/// temporal validation, and `cnf.jwk` proof-of-possession binding are owned by
/// the injected Request Object verifier. This value is the protocol-level
/// summary the wallet core needs after that trust decision.
#[derive(Clone)]
pub struct VerifiedVerifierAttestation {
    /// Attestation `sub` claim. This is the unprefixed verifier identifier.
    subject: String,
    /// Optional attestation `redirect_uris` claim.
    redirect_uris: Option<Vec<String>>,
    /// Canonical public key authenticated by the attestation `cnf.jwk` claim.
    confirmation_public_key: SecretSlice<u8>,
    /// Exclusive attestation expiration time.
    expiration_unix: u64,
}

impl PartialEq for VerifiedVerifierAttestation {
    fn eq(&self, other: &Self) -> bool {
        let left_key = self.confirmation_public_key.expose_secret();
        let right_key = other.confirmation_public_key.expose_secret();
        self.subject == other.subject
            && self.redirect_uris == other.redirect_uris
            && self.expiration_unix == other.expiration_unix
            && left_key.len() == right_key.len()
            && bool::from(left_key.ct_eq(right_key))
    }
}

impl Eq for VerifiedVerifierAttestation {}

impl fmt::Debug for VerifiedVerifierAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedVerifierAttestation")
            .field(
                "redirect_uri_count",
                &self.redirect_uris.as_ref().map(Vec::len),
            )
            .field("claims", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedVerifierAttestation {
    fn zeroize(&mut self) {
        self.subject.zeroize();
        self.redirect_uris.zeroize();
        self.expiration_unix.zeroize();
    }
}

impl Drop for VerifiedVerifierAttestation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedVerifierAttestation {}

impl VerifiedVerifierAttestation {
    /// Build verified attestation evidence after structural validation.
    pub fn new(
        subject: String,
        redirect_uris: Option<Vec<String>>,
        mut confirmation_public_key: Vec<u8>,
        expiration_unix: u64,
    ) -> Result<Self, WalletError> {
        if subject.is_empty() || confirmation_public_key.is_empty() || expiration_unix == 0 {
            confirmation_public_key.zeroize();
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        }
        if let Some(values) = redirect_uris.as_ref() {
            if values.is_empty() || values.iter().any(String::is_empty) {
                return Err(WalletError::new(
                    WalletErrorReason::InvalidVerifierAttestation,
                ));
            }
        }
        Ok(Self {
            subject,
            redirect_uris,
            confirmation_public_key: confirmation_public_key.into(),
            expiration_unix,
        })
    }

    pub(crate) fn validates_signing_key(&self, public_key: &[u8], now_unix: u64) -> bool {
        now_unix != 0
            && now_unix < self.expiration_unix
            && public_key.len() == self.confirmation_public_key.expose_secret().len()
            && bool::from(public_key.ct_eq(self.confirmation_public_key.expose_secret().as_ref()))
    }
}

/// Validate request claims against previously verified verifier attestation evidence.
pub fn validate_verifier_attestation_binding(
    request: &AuthorizationRequestObject,
    attestation: &VerifiedVerifierAttestation,
    request_signing_public_key: &[u8],
    now_unix: u64,
) -> Result<(), WalletError> {
    if !attestation.validates_signing_key(request_signing_public_key, now_unix) {
        return Err(WalletError::new(
            WalletErrorReason::InvalidVerifierAttestation,
        ));
    }
    validate_verifier_attestation_claim_binding(request, attestation)
}

pub(crate) fn validate_verifier_attestation_claim_binding(
    request: &AuthorizationRequestObject,
    attestation: &VerifiedVerifierAttestation,
) -> Result<(), WalletError> {
    let Some(client_id) = request.client_id.as_ref() else {
        return Err(WalletError::new(
            WalletErrorReason::InvalidClientIdentifierPrefix,
        ));
    };
    if client_id.identifier() != attestation.subject {
        return Err(WalletError::new(
            WalletErrorReason::InvalidVerifierAttestation,
        ));
    }
    if let Some(redirect_uris) = attestation.redirect_uris.as_ref() {
        let Some(redirect_uri) = request.redirect_uri.as_deref() else {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        };
        if !redirect_uris.iter().any(|allowed| allowed == redirect_uri) {
            return Err(WalletError::new(
                WalletErrorReason::InvalidVerifierAttestation,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "verifier_attestation_tests.rs"]
mod tests;
