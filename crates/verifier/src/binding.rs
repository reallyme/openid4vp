// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::{
    CanonicalDnsName, ClientIdentifier, ClientIdentifierPrefix, TransactionDataHashAlgorithm,
    ValidatedHttpsEndpoint,
};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{VerifierError, VerifierErrorReason};

/// Minimum bytes required for caller-supplied nonce and state values.
///
/// Sixteen uniformly random bytes provide the 128-bit floor expected for
/// session-binding material. Length cannot prove entropy, but rejecting shorter
/// values prevents trivially guessable bindings such as `"1"`.
pub const MIN_SESSION_BINDING_BYTES: usize = 16;
/// Maximum ordered transaction-data bindings retained in one verifier session.
pub const MAX_TRANSACTION_DATA_BINDINGS: usize = 64;

/// One ordered transaction-data digest bound to one DCQL credential query.
#[derive(Clone, PartialEq, Eq)]
pub struct TransactionDataBinding {
    /// Query whose holder proof must carry this digest.
    pub query_id: QueryId,
    /// Digest algorithm; OpenID4VP currently defines SHA-256 as the default.
    pub algorithm: TransactionDataHashAlgorithm,
    /// Digest over the exact encoded transaction_data string.
    pub digest: [u8; 32],
}

impl fmt::Debug for TransactionDataBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionDataBinding")
            .field("query_id", &self.query_id)
            .field("algorithm", &self.algorithm)
            .field("digest", &"<redacted>")
            .finish()
    }
}

impl Zeroize for TransactionDataBinding {
    fn zeroize(&mut self) {
        self.query_id.zeroize();
        self.digest.zeroize();
    }
}

impl Drop for TransactionDataBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TransactionDataBinding {}

/// Request binding material used to validate an authorization response.
#[derive(Clone, PartialEq, Eq)]
pub struct RequestBinding {
    /// Parsed Client Identifier.
    pub client_id: ClientIdentifier,
    /// Nonce from the Authorization Request.
    pub nonce: String,
    /// Response URI used for direct post modes.
    pub response_uri: Option<String>,
    /// Redirect URI used for front-channel modes.
    pub redirect_uri: Option<String>,
    /// Browser origin bound to Digital Credentials API response modes.
    pub dc_api_origin: Option<String>,
    /// Expiry time in Unix seconds.
    pub expiry_unix: u64,
    /// Ordered transaction-data digests grouped by credential query.
    pub transaction_data_bindings: Vec<TransactionDataBinding>,
}

impl fmt::Debug for RequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestBinding")
            .field("client_id_prefix", &self.client_id.prefix())
            .field("has_response_uri", &self.response_uri.is_some())
            .field("has_redirect_uri", &self.redirect_uri.is_some())
            .field("has_dc_api_origin", &self.dc_api_origin.is_some())
            .field("expiry_unix", &self.expiry_unix)
            .field(
                "transaction_data_binding_count",
                &self.transaction_data_bindings.len(),
            )
            .field("binding_values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for RequestBinding {
    fn zeroize(&mut self) {
        self.client_id.zeroize();
        self.nonce.zeroize();
        self.response_uri.zeroize();
        self.redirect_uri.zeroize();
        self.dc_api_origin.zeroize();
        self.expiry_unix.zeroize();
        self.transaction_data_bindings.zeroize();
    }
}

impl Drop for RequestBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RequestBinding {}

/// Validate request binding freshness and required endpoints.
pub fn validate_request_binding(
    binding: &RequestBinding,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if now_unix == 0 {
        return Err(VerifierError::new(VerifierErrorReason::ClockUnavailable));
    }
    if binding.nonce.len() < MIN_SESSION_BINDING_BYTES {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    if binding.transaction_data_bindings.len() > MAX_TRANSACTION_DATA_BINDINGS {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    let has_endpoint = binding.response_uri.is_some() || binding.redirect_uri.is_some();
    match (has_endpoint, binding.dc_api_origin.as_deref()) {
        (true, None) => {}
        (false, Some(origin)) => validate_dc_api_origin(origin)?,
        (false, None) | (true, Some(_)) => {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
    }
    if let Some(response_uri) = binding.response_uri.as_deref() {
        validate_endpoint_uri(response_uri)?;
    }
    if let Some(redirect_uri) = binding.redirect_uri.as_deref() {
        validate_endpoint_uri(redirect_uri)?;
    }
    validate_endpoint_client_identifier_binding(binding)?;
    // OAuth/JWT expiry is an exclusive upper bound: the binding is no longer
    // valid at the instant represented by `expiry_unix`.
    if binding.expiry_unix == 0 || now_unix >= binding.expiry_unix {
        return Err(VerifierError::new(VerifierErrorReason::BindingExpired));
    }
    Ok(())
}

fn validate_dc_api_origin(origin: &str) -> Result<(), VerifierError> {
    let parsed =
        Url::parse(origin).map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    Ok(())
}

fn validate_endpoint_uri(uri: &str) -> Result<(), VerifierError> {
    ValidatedHttpsEndpoint::parse(uri)
        .map(|_| ())
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRequestUri))
}

fn validate_endpoint_client_identifier_binding(
    binding: &RequestBinding,
) -> Result<(), VerifierError> {
    match binding.client_id.prefix() {
        ClientIdentifierPrefix::X509SanDns => {
            let expected_host = binding.client_id.identifier();
            if let Some(response_uri) = binding.response_uri.as_deref() {
                validate_endpoint_host_matches_client_id(response_uri, expected_host)?;
            }
            if let Some(redirect_uri) = binding.redirect_uri.as_deref() {
                validate_endpoint_host_matches_client_id(redirect_uri, expected_host)?;
            }
        }
        ClientIdentifierPrefix::X509Hash => {
            // The certificate hash prefix binds through host-validated TLS
            // certificate material supplied by the runtime/JWS verifier. This
            // layer validates endpoint shape but cannot reconstruct that
            // certificate chain from a URI string alone.
        }
        ClientIdentifierPrefix::None
        | ClientIdentifierPrefix::RedirectUri
        | ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier
        | ClientIdentifierPrefix::VerifierAttestation
        | ClientIdentifierPrefix::Origin => {}
    }
    Ok(())
}

fn validate_endpoint_host_matches_client_id(
    endpoint: &str,
    expected_host: &str,
) -> Result<(), VerifierError> {
    let endpoint = ValidatedHttpsEndpoint::parse(endpoint)
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRequestUri))?;
    let expected = CanonicalDnsName::parse_reference(expected_host)
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
    if !endpoint.host_matches_dns_name(&expected) {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    Ok(())
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;
