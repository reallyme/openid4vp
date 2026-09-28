// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use url::{Host, Url};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Policy baseline:
// - RFC 3986 Sections 3.2 and 6.2 define authority parsing and syntax-based
//   normalization for URI comparison.
// - RFC 8399 Section 2.3 updates RFC 5280 Section 7.2: certificate dNSName
//   equality is a case-insensitive exact comparison of the entire A-label name.
// - OpenID4VP 1.0 Final Section 5.9.3 separately binds the response endpoint
//   FQDN and the client identifier to the leaf certificate SAN.
// Trailing-root dots and percent-encoded authorities are valid in broader URI
// contexts but rejected here to keep one unambiguous security identity.

/// Maximum accepted HTTPS endpoint length at the protocol boundary.
pub const MAX_HTTPS_ENDPOINT_BYTES: usize = 8 * 1024;
/// Maximum accepted DNS name length, excluding a root-label trailing dot.
pub const MAX_DNS_NAME_BYTES: usize = 253;

/// Stable endpoint and DNS validation failure.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP endpoint identity error: {reason:?}")]
pub struct EndpointIdentityError {
    reason: EndpointIdentityErrorReason,
}

impl EndpointIdentityError {
    const fn new(reason: EndpointIdentityErrorReason) -> Self {
        Self { reason }
    }

    /// Return the stable failure reason.
    pub const fn reason(self) -> EndpointIdentityErrorReason {
        self.reason
    }
}

/// Stable endpoint and DNS validation failure reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointIdentityErrorReason {
    /// The input exceeded a fixed protocol bound.
    InputTooLarge,
    /// The endpoint is not an absolute HTTPS URL permitted by policy.
    InvalidHttpsEndpoint,
    /// The value is not a canonical DNS reference identifier.
    InvalidDnsReferenceIdentifier,
    /// The certificate SAN is not a canonical RFC 5280 `dNSName` value.
    InvalidDnsSan,
}

/// Canonical A-label DNS name produced by strict UTS #46/IDNA processing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalDnsName(String);

impl CanonicalDnsName {
    /// Parse a DNS reference identifier and convert U-labels to A-labels.
    pub fn parse_reference(value: &str) -> Result<Self, EndpointIdentityError> {
        parse_dns_name(
            value,
            false,
            EndpointIdentityErrorReason::InvalidDnsReferenceIdentifier,
        )
    }

    /// Parse an RFC 5280 `dNSName` SAN.
    ///
    /// RFC 8399 Section 2.3 requires an IA5String A-label and exact
    /// case-insensitive
    /// whole-name equality. Wildcards are therefore deliberately rejected;
    /// TLS wildcard hostname matching is not the OpenID4VP client-id rule.
    pub fn parse_rfc5280_san(value: &str) -> Result<Self, EndpointIdentityError> {
        if !value.is_ascii() || value.contains('*') {
            return Err(EndpointIdentityError::new(
                EndpointIdentityErrorReason::InvalidDnsSan,
            ));
        }
        parse_dns_name(value, true, EndpointIdentityErrorReason::InvalidDnsSan)
    }

    /// Return the canonical lower-case A-label form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CanonicalDnsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalDnsName(<redacted>)")
    }
}

impl Zeroize for CanonicalDnsName {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CanonicalDnsName {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CanonicalDnsName {}

/// Canonical endpoint host with IP literals represented semantically.
#[derive(Clone, PartialEq, Eq)]
pub enum CanonicalEndpointHost {
    /// IDNA2008 A-label DNS host.
    Dns(CanonicalDnsName),
    /// Four-octet IPv4 address.
    Ipv4(Ipv4Addr),
    /// Sixteen-octet IPv6 address.
    Ipv6(Ipv6Addr),
}

impl fmt::Debug for CanonicalEndpointHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(_) => formatter.write_str("CanonicalEndpointHost::Dns(<redacted>)"),
            Self::Ipv4(_) => formatter.write_str("CanonicalEndpointHost::Ipv4(<redacted>)"),
            Self::Ipv6(_) => formatter.write_str("CanonicalEndpointHost::Ipv6(<redacted>)"),
        }
    }
}

impl Zeroize for CanonicalEndpointHost {
    fn zeroize(&mut self) {
        if let Self::Dns(name) = self {
            name.zeroize();
        }
    }
}

impl Drop for CanonicalEndpointHost {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CanonicalEndpointHost {}

/// Audited, canonicalized HTTPS endpoint identity.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedHttpsEndpoint {
    host: CanonicalEndpointHost,
}

impl ValidatedHttpsEndpoint {
    /// Parse an absolute HTTPS URL under the OpenID4VP endpoint policy.
    pub fn parse(value: &str) -> Result<Self, EndpointIdentityError> {
        if value.len() > MAX_HTTPS_ENDPOINT_BYTES {
            return Err(EndpointIdentityError::new(
                EndpointIdentityErrorReason::InputTooLarge,
            ));
        }
        if value.is_empty()
            || value
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || raw_authority_is_invalid(value)
        {
            return Err(EndpointIdentityError::new(
                EndpointIdentityErrorReason::InvalidHttpsEndpoint,
            ));
        }

        let url = Url::parse(value).map_err(|_| {
            EndpointIdentityError::new(EndpointIdentityErrorReason::InvalidHttpsEndpoint)
        })?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            zeroize_url(url);
            return Err(EndpointIdentityError::new(
                EndpointIdentityErrorReason::InvalidHttpsEndpoint,
            ));
        }

        let host = match url.host() {
            Some(Host::Domain(domain)) => {
                CanonicalDnsName::parse_reference(domain).map(CanonicalEndpointHost::Dns)
            }
            Some(Host::Ipv4(address)) => Ok(CanonicalEndpointHost::Ipv4(address)),
            Some(Host::Ipv6(address)) => Ok(CanonicalEndpointHost::Ipv6(address)),
            None => Err(EndpointIdentityError::new(
                EndpointIdentityErrorReason::InvalidHttpsEndpoint,
            )),
        };
        // `Url` owns the entire serialized endpoint, potentially including
        // sensitive path/query data. Consume and wipe it after extracting the
        // only value this security type retains: the canonical host.
        zeroize_url(url);
        Ok(Self { host: host? })
    }

    /// Return the canonical authority host.
    #[must_use]
    pub const fn host(&self) -> &CanonicalEndpointHost {
        &self.host
    }

    /// Compare an endpoint DNS host with a canonical DNS identity.
    #[must_use]
    pub fn host_matches_dns_name(&self, expected: &CanonicalDnsName) -> bool {
        matches!(&self.host, CanonicalEndpointHost::Dns(actual) if actual == expected)
    }
}

impl fmt::Debug for ValidatedHttpsEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedHttpsEndpoint")
            .field("host", &self.host)
            .finish()
    }
}

impl Zeroize for ValidatedHttpsEndpoint {
    fn zeroize(&mut self) {
        self.host.zeroize();
    }
}

impl Drop for ValidatedHttpsEndpoint {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ValidatedHttpsEndpoint {}

fn parse_dns_name(
    value: &str,
    already_ascii: bool,
    invalid_reason: EndpointIdentityErrorReason,
) -> Result<CanonicalDnsName, EndpointIdentityError> {
    let invalid_dns_name = || EndpointIdentityError::new(invalid_reason);
    if value.is_empty()
        || value.len() > MAX_DNS_NAME_BYTES
        || value.ends_with('.')
        || value.starts_with('.')
        || value.contains("..")
    {
        return Err(invalid_dns_name());
    }
    if already_ascii && !value.is_ascii() {
        return Err(invalid_dns_name());
    }
    // RFC 8399 Section 2.3 requires U-label reference identifiers to be
    // converted to A-labels before comparison. The strict profile enables
    // STD3 character rules, hyphen checks, and DNS-length verification rather
    // than inheriting a browser-oriented compatibility profile from URL
    // parsing. Certificate SAN input is already constrained to IA5String.
    // Apply strict IDNA processing to certificate input too. Merely checking
    // IA5String syntax would accept malformed `xn--` labels that are ASCII but
    // are not valid A-labels under RFC 8399 Section 2.3.
    let ascii_name =
        Zeroizing::new(idna::domain_to_ascii_strict(value).map_err(|_| invalid_dns_name())?);
    let Host::Domain(mut domain) = Host::parse(&ascii_name).map_err(|_| invalid_dns_name())? else {
        return Err(invalid_dns_name());
    };
    if domain.len() > MAX_DNS_NAME_BYTES
        || domain.ends_with('.')
        || domain.contains('*')
        || !domain.split('.').all(is_valid_dns_label)
    {
        domain.zeroize();
        return Err(invalid_dns_name());
    }
    domain.make_ascii_lowercase();
    Ok(CanonicalDnsName(domain))
}

fn zeroize_url(url: Url) {
    let mut serialized: String = url.into();
    serialized.zeroize();
}

fn is_valid_dns_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    let bytes = label.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    let Some(last) = bytes.last() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn raw_authority_is_invalid(value: &str) -> bool {
    // RFC 3986 Section 3.2 uses `@` as the userinfo delimiter and does not
    // admit reverse solidus as a URI authority character. Reject both before
    // WHATWG URL parsing so browser-compatible normalization cannot silently
    // reinterpret an attacker-controlled security identity. This also rejects
    // empty userinfo (`https://@host`), which `Url::username()` cannot expose.
    if value.contains('\\') {
        return true;
    }
    let Some(scheme_end) = value.find("://") else {
        return true;
    };
    let Some(authority_start) = scheme_end.checked_add(3) else {
        return true;
    };
    let Some(after_scheme) = value.get(authority_start..) else {
        return true;
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    after_scheme.get(..authority_end).is_none_or(|authority| {
        authority.is_empty() || authority.contains('%') || authority.contains('@')
    })
}

#[cfg(test)]
#[path = "endpoint_tests.rs"]
mod tests;
