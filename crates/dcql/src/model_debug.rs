// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use crate::model::{
    ClaimQuery, ClaimValue, ClaimsPath, ClaimsPathComponent, CredentialQuery, DcqlQuery,
    TrustedAuthorityQuery,
};

impl fmt::Debug for DcqlQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DcqlQuery")
            .field("credential_count", &self.credentials.len())
            .field(
                "credential_set_count",
                &self.credential_sets.as_ref().map(Vec::len),
            )
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for CredentialQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialQuery")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("multiple", &self.multiple)
            .field("has_meta", &!self.meta.is_empty())
            .field(
                "trusted_authority_count",
                &self.trusted_authorities.as_ref().map(Vec::len),
            )
            .field(
                "require_cryptographic_holder_binding",
                &self.require_cryptographic_holder_binding,
            )
            .field("claim_count", &self.claims.as_ref().map(Vec::len))
            .field("claim_set_count", &self.claim_sets.as_ref().map(Vec::len))
            .field("constraint_values", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for TrustedAuthorityQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedAuthorityQuery")
            .field("authority_type", &self.authority_type)
            .field("value_count", &self.values.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ClaimQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimQuery")
            .field("id", &self.id)
            .field("path", &"<redacted>")
            .field("value_count", &self.values.as_ref().map(Vec::len))
            .field("intent_to_retain", &self.intent_to_retain)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ClaimsPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimsPath")
            .field("component_count", &self.0.len())
            .field("components", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ClaimsPathComponent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Name(_) => "name",
            Self::Index(_) => "index",
            Self::All => "all",
        };
        formatter
            .debug_struct("ClaimsPathComponent")
            .field("kind", &kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for ClaimValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::String(_) => "string",
            Self::Integer(_) => "integer",
            Self::Boolean(_) => "boolean",
        };
        formatter
            .debug_struct("ClaimValue")
            .field("kind", &kind)
            .field("value", &"<redacted>")
            .finish()
    }
}
