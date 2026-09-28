// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use reallyme_openid4vp_types::{
    classify_request_object_jwt, CanonicalEndpointHost, ValidatedHttpsEndpoint,
};
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::build_request_uri_http_request::{
    build_request_uri_http_request, RequestUriHttpRequest,
};
use crate::error::{HttpAdapterError, HttpAdapterErrorReason};

const MAX_RESOLVED_REQUEST_URI_ADDRESSES: usize = 16;
const DEFAULT_MAX_REQUEST_JWT_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_MEDIA_TYPE_BYTES: usize = 256;

/// HTTP response containing a Request Object JWT.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestObjectHttpResponse {
    /// HTTP status observed from the final response without redirect following.
    status: u16,
    /// Raw Content-Type observed from the final response.
    media_type: String,
    /// Compact Request Object JWT.
    jwt: String,
    /// Actual peer address used by the transport after DNS resolution.
    connected_ip: IpAddr,
    /// Redirects followed by the HTTP implementation.
    redirect_count: u32,
}

impl fmt::Debug for RequestObjectHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestObjectHttpResponse")
            .field("jwt_byte_len", &self.jwt.len())
            .field("jwt", &"<redacted>")
            .finish()
    }
}

impl RequestObjectHttpResponse {
    /// Construct a response with transport-observed network metadata.
    pub fn new(
        status: u16,
        media_type: String,
        jwt: String,
        connected_ip: IpAddr,
        redirect_count: u32,
    ) -> Self {
        Self {
            status,
            media_type,
            jwt,
            connected_ip,
            redirect_count,
        }
    }

    fn into_jwt(mut self) -> String {
        core::mem::take(&mut self.jwt)
    }
}

/// Mandatory fetch constraints enforced by a concrete HTTP adapter while it
/// streams the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestUriFetchConstraints<'a> {
    /// Maximum response-body bytes read from the network.
    pub max_response_bytes: usize,
    /// Redirect following is prohibited to keep the validated authority fixed.
    pub allow_redirects: bool,
    /// Public addresses resolved and approved before any request is sent.
    ///
    /// The adapter must connect only to one of these exact addresses while
    /// preserving the original URI host for TLS SNI and certificate checks.
    pub resolved_ips: &'a [IpAddr],
}

impl Zeroize for RequestObjectHttpResponse {
    fn zeroize(&mut self) {
        self.media_type.zeroize();
        self.jwt.zeroize();
    }
}

impl Drop for RequestObjectHttpResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RequestObjectHttpResponse {}

/// Transport boundary for resolving `request_uri`.
pub trait RequestUriFetcher: Send + Sync {
    /// Resolve the canonical endpoint host without sending an HTTP request.
    ///
    /// DNS adapters must return every address they could select for the
    /// connection. The protocol layer rejects the entire set when any answer
    /// is private, local, reserved, or otherwise unsafe.
    fn resolve_request_uri_host(
        &self,
        host: &CanonicalEndpointHost,
    ) -> Result<Vec<IpAddr>, HttpAdapterError>;

    /// Fetch a Request Object JWT without embedding network I/O in protocol crates.
    fn fetch_request_object(
        &self,
        uri: &str,
        request: &RequestUriHttpRequest,
        constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError>;
}

/// HTTP transport resolution policy.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestUriResolutionPolicy {
    /// Maximum accepted compact Request Object JWT size in bytes.
    pub max_request_jwt_bytes: usize,
    /// Wallet-generated nonce to POST when `request_uri_method=post`.
    pub post_wallet_nonce: Option<String>,
    /// Network class permitted for request-URI resolution.
    pub network_policy: RequestUriNetworkPolicy,
}

/// Network class permitted for request-URI resolution.
///
/// Production callers should retain [`Self::PublicOnly`]. The loopback-only
/// mode exists for isolated local conformance environments and deliberately
/// rejects public and non-loopback private destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestUriNetworkPolicy {
    /// Require a public DNS name or IP address and reject SSRF-sensitive ranges.
    PublicOnly,
    /// Require `localhost`, a `.localhost` name, or a loopback IP address.
    LoopbackOnly,
}

impl fmt::Debug for RequestUriResolutionPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestUriResolutionPolicy")
            .field("max_request_jwt_bytes", &self.max_request_jwt_bytes)
            .field("has_post_wallet_nonce", &self.post_wallet_nonce.is_some())
            .field("network_policy", &self.network_policy)
            .finish()
    }
}

impl Zeroize for RequestUriResolutionPolicy {
    fn zeroize(&mut self) {
        self.post_wallet_nonce.zeroize();
    }
}

impl Drop for RequestUriResolutionPolicy {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RequestUriResolutionPolicy {}

impl Default for RequestUriResolutionPolicy {
    fn default() -> Self {
        Self {
            max_request_jwt_bytes: DEFAULT_MAX_REQUEST_JWT_BYTES,
            post_wallet_nonce: None,
            network_policy: RequestUriNetworkPolicy::PublicOnly,
        }
    }
}

impl RequestUriResolutionPolicy {
    /// Select the exact network class permitted for request-URI resolution.
    #[must_use]
    pub const fn with_network_policy(mut self, network_policy: RequestUriNetworkPolicy) -> Self {
        self.network_policy = network_policy;
        self
    }
}

/// Resolve a parsed `request_uri` transport into a by-value Request Object JWT.
pub fn resolve_request_uri_transport(
    transport: AuthorizationRequestTransport,
    fetcher: &impl RequestUriFetcher,
    policy: RequestUriResolutionPolicy,
) -> Result<AuthorizationRequestTransport, HttpAdapterError> {
    let AuthorizationRequestTransport::RequestUri {
        uri,
        method,
        wallet_nonce,
        expected_client_id,
    } = &transport
    else {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriRequired,
        ));
    };

    if uri
        .split_once(':')
        .is_none_or(|(scheme, _)| !scheme.eq_ignore_ascii_case("https"))
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriMustBeHttps,
        ));
    }
    let endpoint = ValidatedHttpsEndpoint::parse(uri)
        .map_err(|_| HttpAdapterError::new(HttpAdapterErrorReason::UnsafeRequestUri))?;
    validate_endpoint_host(endpoint.host(), policy.network_policy)?;
    let resolved_ips = fetcher.resolve_request_uri_host(endpoint.host())?;
    validate_resolved_ips(&resolved_ips, policy.network_policy)?;

    let expected_wallet_nonce = wallet_nonce
        .clone()
        .or_else(|| policy.post_wallet_nonce.clone());
    let request = build_request_uri_http_request(*method, expected_wallet_nonce.as_deref())?;
    let response = fetcher.fetch_request_object(
        uri,
        &request,
        RequestUriFetchConstraints {
            max_response_bytes: policy.max_request_jwt_bytes,
            allow_redirects: false,
            resolved_ips: &resolved_ips,
        },
    )?;

    if response.redirect_count != 0 {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    if response.status != 200 {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectHttpStatus,
        ));
    }
    validate_request_object_media_type(&response.media_type)?;
    validate_resolved_ip(response.connected_ip, policy.network_policy)?;
    if !resolved_ips.contains(&response.connected_ip) {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }

    if response.jwt.is_empty() {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectEncoding,
        ));
    }

    if response.jwt.len() > policy.max_request_jwt_bytes {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestObjectTooLarge,
        ));
    }

    classify_request_object_jwt(&response.jwt)
        .map_err(|_| HttpAdapterError::new(HttpAdapterErrorReason::InvalidRequestObjectEncoding))?;

    let jwt = response.into_jwt();
    Ok(AuthorizationRequestTransport::RequestJwt {
        jwt,
        expected_client_id: expected_client_id.clone(),
        expected_wallet_nonce,
    })
}

fn validate_request_object_media_type(value: &str) -> Result<(), HttpAdapterError> {
    if value.is_empty() || value.len() > MAX_RESPONSE_MEDIA_TYPE_BYTES {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectMediaType,
        ));
    }
    let mut parts = value.split(';');
    let Some(essence) = parts.next().map(str::trim) else {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectMediaType,
        ));
    };
    if !essence.eq_ignore_ascii_case(reallyme_openid4vp_types::REQUEST_OBJECT_MEDIA_TYPE) {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::InvalidRequestObjectMediaType,
        ));
    }
    let mut parameter_names = std::collections::BTreeSet::new();
    for parameter in parts {
        let Some((name, parameter_value)) = parameter.trim().split_once('=') else {
            return Err(HttpAdapterError::new(
                HttpAdapterErrorReason::InvalidRequestObjectMediaType,
            ));
        };
        let normalized_name = name.trim().to_ascii_lowercase();
        if normalized_name.is_empty()
            || parameter_value.trim().is_empty()
            || !normalized_name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'-')
            })
            || !parameter_names.insert(normalized_name)
        {
            return Err(HttpAdapterError::new(
                HttpAdapterErrorReason::InvalidRequestObjectMediaType,
            ));
        }
    }
    Ok(())
}

fn validate_endpoint_host(
    host: &CanonicalEndpointHost,
    network_policy: RequestUriNetworkPolicy,
) -> Result<(), HttpAdapterError> {
    match host {
        CanonicalEndpointHost::Dns(name) => {
            let name = name.as_str();
            let is_loopback_name = name.eq_ignore_ascii_case("localhost")
                || name
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty());
            match network_policy {
                RequestUriNetworkPolicy::PublicOnly if is_loopback_name => unsafe_uri_error(),
                RequestUriNetworkPolicy::LoopbackOnly if !is_loopback_name => unsafe_uri_error(),
                RequestUriNetworkPolicy::PublicOnly | RequestUriNetworkPolicy::LoopbackOnly => {
                    Ok(())
                }
            }
        }
        CanonicalEndpointHost::Ipv4(ip) => validate_resolved_ip(IpAddr::V4(*ip), network_policy),
        CanonicalEndpointHost::Ipv6(ip) => validate_resolved_ip(IpAddr::V6(*ip), network_policy),
    }
}

fn validate_resolved_ips(
    resolved_ips: &[IpAddr],
    network_policy: RequestUriNetworkPolicy,
) -> Result<(), HttpAdapterError> {
    if resolved_ips.is_empty() || resolved_ips.len() > MAX_RESOLVED_REQUEST_URI_ADDRESSES {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    for ip in resolved_ips {
        validate_resolved_ip(*ip, network_policy)?;
    }
    Ok(())
}

fn validate_resolved_ip(
    ip: IpAddr,
    network_policy: RequestUriNetworkPolicy,
) -> Result<(), HttpAdapterError> {
    match network_policy {
        RequestUriNetworkPolicy::PublicOnly => reject_unsafe_ip(ip),
        RequestUriNetworkPolicy::LoopbackOnly if ip.is_loopback() => Ok(()),
        RequestUriNetworkPolicy::LoopbackOnly => unsafe_uri_error(),
    }
}

const fn unsafe_uri_error() -> Result<(), HttpAdapterError> {
    Err(HttpAdapterError::new(
        HttpAdapterErrorReason::UnsafeRequestUri,
    ))
}

fn reject_unsafe_ip(ip: IpAddr) -> Result<(), HttpAdapterError> {
    match ip {
        IpAddr::V4(ip) => reject_unsafe_ipv4(ip),
        IpAddr::V6(ip) => reject_unsafe_ipv6(ip),
    }
}

fn reject_unsafe_ipv4(ip: Ipv4Addr) -> Result<(), HttpAdapterError> {
    let octets = ip.octets();
    let shared_address_space = octets[0] == 100 && (64..=127).contains(&octets[1]);
    let benchmarking = octets[0] == 198 && (18..=19).contains(&octets[1]);
    let protocol_assignment = octets[0] == 192 && octets[1] == 0 && octets[2] == 0;
    let reserved = octets[0] >= 240 || octets[0] == 0;
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || shared_address_space
        || benchmarking
        || protocol_assignment
        || reserved
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    Ok(())
}

fn reject_unsafe_ipv6(ip: Ipv6Addr) -> Result<(), HttpAdapterError> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return reject_unsafe_ipv4(mapped);
    }
    let segments = ip.segments();
    let global_unicast_2000_over_3 = (segments[0] & 0xe000) == 0x2000;
    // IANA's special-purpose registry reserves 2001::/23 for transition,
    // benchmarking, discard, ORCHID, and other protocol assignments. 6to4 is
    // independently allocated from 2002::/16 and can relay to an embedded IPv4
    // destination, so neither class is a permissible HTTP destination.
    let ietf_protocol_assignments = segments[0] == 0x2001 && segments[1] <= 0x01ff;
    let six_to_four = segments[0] == 0x2002;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let documentation_v2 = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0;
    let segment_routing_sids = segments[0] == 0x5f00;
    let discard_only = segments[0] == 0x0100 && segments[1] == 0;
    let nat64_well_known = segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0);
    let nat64_local = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1;
    if !global_unicast_2000_over_3
        || ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || documentation
        || documentation_v2
        || segment_routing_sids
        || discard_only
        || nat64_well_known
        || nat64_local
        || ietf_protocol_assignments
        || six_to_four
    {
        return Err(HttpAdapterError::new(
            HttpAdapterErrorReason::UnsafeRequestUri,
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "resolve_request_uri_tests.rs"]
mod tests;
