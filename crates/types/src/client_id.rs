// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// OpenID4VP 1.0 final Client Identifier Prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientIdentifierPrefix {
    /// No explicit prefix. Profiles may define fallback behavior.
    None,
    /// `redirect_uri`.
    RedirectUri,
    /// `openid_federation`.
    OpenIdFederation,
    /// `decentralized_identifier`.
    DecentralizedIdentifier,
    /// `verifier_attestation`.
    VerifierAttestation,
    /// `x509_san_dns`.
    X509SanDns,
    /// `x509_hash`.
    X509Hash,
    /// `origin`, reserved for Digital Credentials API processing.
    Origin,
}

impl ClientIdentifierPrefix {
    /// Return the wire prefix string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::RedirectUri => "redirect_uri",
            Self::OpenIdFederation => "openid_federation",
            Self::DecentralizedIdentifier => "decentralized_identifier",
            Self::VerifierAttestation => "verifier_attestation",
            Self::X509SanDns => "x509_san_dns",
            Self::X509Hash => "x509_hash",
            Self::Origin => "origin",
        }
    }
}

/// Parsed Client Identifier with its final-spec prefix.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientIdentifier {
    /// Prefix used to bind verifier trust and metadata lookup.
    prefix: ClientIdentifierPrefix,
    /// Original identifier value after removing the prefix.
    identifier: String,
}

impl fmt::Debug for ClientIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientIdentifier")
            .field("prefix", &self.prefix)
            .field("identifier", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ClientIdentifier {
    fn zeroize(&mut self) {
        self.identifier.zeroize();
    }
}

impl Drop for ClientIdentifier {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClientIdentifier {}

impl ClientIdentifier {
    /// Parse an OpenID4VP Client Identifier.
    pub fn parse(value: &str) -> Result<Self, OpenId4vpTypeError> {
        if value.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyValue,
            ));
        }

        let Some((prefix, identifier)) = value.split_once(':') else {
            return Ok(Self {
                prefix: ClientIdentifierPrefix::None,
                identifier: value.to_owned(),
            });
        };

        if identifier.is_empty() {
            return Err(OpenId4vpTypeError::new(
                OpenId4vpTypeErrorReason::EmptyValue,
            ));
        }

        let prefix = match prefix {
            "redirect_uri" => ClientIdentifierPrefix::RedirectUri,
            "openid_federation" => ClientIdentifierPrefix::OpenIdFederation,
            "decentralized_identifier" => ClientIdentifierPrefix::DecentralizedIdentifier,
            "verifier_attestation" => ClientIdentifierPrefix::VerifierAttestation,
            "x509_san_dns" => ClientIdentifierPrefix::X509SanDns,
            "x509_hash" => ClientIdentifierPrefix::X509Hash,
            "origin" => ClientIdentifierPrefix::Origin,
            _ => {
                return Err(OpenId4vpTypeError::new(
                    OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix,
                ));
            }
        };

        Ok(Self {
            prefix,
            identifier: identifier.to_owned(),
        })
    }

    /// Return the full wire client identifier.
    pub fn to_wire_value(&self) -> String {
        if self.prefix == ClientIdentifierPrefix::None {
            return self.identifier.clone();
        }
        let mut value = self.prefix.as_str().to_owned();
        value.push(':');
        value.push_str(&self.identifier);
        value
    }

    /// Return the validated client identifier prefix.
    #[must_use]
    pub const fn prefix(&self) -> ClientIdentifierPrefix {
        self.prefix
    }

    /// Return the validated identifier component without its prefix.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }
}

impl Serialize for ClientIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_wire_value())
    }
}

impl<'de> Deserialize<'de> for ClientIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .map_err(|_| serde::de::Error::custom("invalid OpenID4VP client identifier"))
    }
}

#[cfg(test)]
#[path = "client_id_tests.rs"]
mod tests;
