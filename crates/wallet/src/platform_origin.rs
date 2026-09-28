// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{WalletError, WalletErrorReason};

/// Browser-platform receipt for the origin invoking the Digital Credentials API.
///
/// Construct this only at the adapter boundary from the browser's authenticated
/// calling-origin primitive. Request JSON is never an acceptable source.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPlatformOrigin {
    value: String,
}

impl VerifiedPlatformOrigin {
    /// Retain a canonical HTTPS origin asserted by the browser security context.
    pub fn from_browser_security_context(value: String) -> Result<Self, WalletError> {
        let parsed = Url::parse(&value)
            .map_err(|_| WalletError::new(WalletErrorReason::InvalidPlatformOrigin))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.origin().ascii_serialization() != value
        {
            return Err(WalletError::new(WalletErrorReason::InvalidPlatformOrigin));
        }
        Ok(Self { value })
    }

    /// Borrow the canonical origin serialization.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for VerifiedPlatformOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedPlatformOrigin(<redacted>)")
    }
}

impl Zeroize for VerifiedPlatformOrigin {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for VerifiedPlatformOrigin {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedPlatformOrigin {}

/// Authenticated transport context for signed wallet Request Objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletInvocationContext {
    /// Cross-device or same-device redirect/direct-post invocation.
    ProtocolTransport,
    /// Browser Digital Credentials API invocation with authenticated origin.
    DigitalCredentialsApi(VerifiedPlatformOrigin),
}

impl WalletInvocationContext {
    pub(crate) fn expected_origin(&self) -> Option<&str> {
        match self {
            Self::ProtocolTransport => None,
            Self::DigitalCredentialsApi(origin) => Some(origin.as_str()),
        }
    }
}
