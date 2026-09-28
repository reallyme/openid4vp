// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{ClientIdentifier, ClientIdentifierPrefix};
use sha2::{Digest, Sha256};
#[cfg(feature = "jose")]
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WalletError, WalletErrorReason};

/// Atomic trust-adapter receipt binding a DID or federation subject to the
/// exact Request Object verification key.
///
/// The host resolver is responsible for DID verification-method authorization
/// or federation trust-chain evaluation. The wallet rechecks both the subject
/// and key after signature verification, so an unverified `client_id` can be
/// used only as a lookup hint and cannot select trust for another subject.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedClientIdentifierBinding {
    subject: ClientIdentifier,
    verification_key_sha256: [u8; 32],
}

impl VerifiedClientIdentifierBinding {
    /// Construct a receipt from a completed DID or federation trust decision.
    pub fn new(subject: ClientIdentifier, verification_key: &[u8]) -> Result<Self, WalletError> {
        if verification_key.is_empty()
            || !matches!(
                subject.prefix(),
                ClientIdentifierPrefix::DecentralizedIdentifier
                    | ClientIdentifierPrefix::OpenIdFederation
            )
        {
            return Err(WalletError::new(
                WalletErrorReason::InvalidClientIdentifierTrustBinding,
            ));
        }
        Ok(Self {
            subject,
            verification_key_sha256: Sha256::digest(verification_key).into(),
        })
    }

    #[cfg(feature = "jose")]
    pub(crate) fn validates(&self, subject: &ClientIdentifier, verification_key: &[u8]) -> bool {
        let actual: [u8; 32] = Sha256::digest(verification_key).into();
        self.subject == *subject && bool::from(self.verification_key_sha256.ct_eq(&actual))
    }
}

impl fmt::Debug for VerifiedClientIdentifierBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedClientIdentifierBinding(<redacted>)")
    }
}

impl Zeroize for VerifiedClientIdentifierBinding {
    fn zeroize(&mut self) {
        self.subject.zeroize();
        self.verification_key_sha256.zeroize();
    }
}

impl Drop for VerifiedClientIdentifierBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedClientIdentifierBinding {}
