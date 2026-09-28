// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::{
    AuthorizationRequestObject, CanonicalDnsName, ClientIdentifier, ClientIdentifierPrefix,
    ResponseMode, ValidatedHttpsEndpoint,
};

use crate::{VerifiedX509CertificateBinding, WalletError, WalletErrorReason};

/// Validate X.509 client identity and wallet-side response endpoint bindings.
pub fn validate_response_endpoint_binding(
    request: &AuthorizationRequestObject,
    client_id: &ClientIdentifier,
    certificate_binding: Option<&VerifiedX509CertificateBinding>,
) -> Result<(), WalletError> {
    validate_response_mode_endpoints(request)?;
    match client_id.prefix() {
        ClientIdentifierPrefix::X509SanDns => {
            // OpenID4VP 1.0 Final Section 5.9.3 and RFC 8399 Section 2.3
            // require two independent checks: exact SAN identity and endpoint
            // FQDN binding. A valid certificate path alone satisfies neither.
            let identifier = CanonicalDnsName::parse_reference(client_id.identifier())
                .map_err(|_| WalletError::new(WalletErrorReason::X509CertificateSanMismatch))?;
            let binding = certificate_binding
                .ok_or_else(|| WalletError::new(WalletErrorReason::MissingX509CertificateChain))?;
            if !binding.contains_dns_name(&identifier) {
                return Err(WalletError::new(
                    WalletErrorReason::X509CertificateSanMismatch,
                ));
            }
            validate_dns_bound_endpoints(request, &identifier)?;
        }
        ClientIdentifierPrefix::X509Hash => {
            let binding = certificate_binding
                .ok_or_else(|| WalletError::new(WalletErrorReason::MissingX509CertificateChain))?;
            if !binding.hash_matches(client_id.identifier()) {
                return Err(WalletError::new(
                    WalletErrorReason::X509CertificateHashMismatch,
                ));
            }
            // OpenID4VP 1.0 Final Section 5.9.3 defines x509_hash only as
            // base64url(SHA-256(DER leaf)); it does not derive an endpoint host
            // from the digest. URI trust remains a separate deployment policy.
            validate_endpoint_shapes(request)?;
        }
        ClientIdentifierPrefix::None
        | ClientIdentifierPrefix::RedirectUri
        | ClientIdentifierPrefix::OpenIdFederation
        | ClientIdentifierPrefix::DecentralizedIdentifier
        | ClientIdentifierPrefix::VerifierAttestation
        | ClientIdentifierPrefix::Origin => validate_endpoint_shapes(request)?,
    }
    Ok(())
}

fn validate_response_mode_endpoints(
    request: &AuthorizationRequestObject,
) -> Result<(), WalletError> {
    let valid = match request.response_mode {
        None | Some(ResponseMode::Fragment | ResponseMode::FormPost) => {
            request.redirect_uri.is_some() && request.response_uri.is_none()
        }
        Some(ResponseMode::DirectPost | ResponseMode::DirectPostJwt) => {
            request.response_uri.is_some() && request.redirect_uri.is_none()
        }
        Some(ResponseMode::DcApi | ResponseMode::DcApiJwt) => {
            request.response_uri.is_none() && request.redirect_uri.is_none()
        }
    };
    if !valid {
        return Err(WalletError::new(WalletErrorReason::InvalidRequestObject));
    }
    Ok(())
}

fn validate_dns_bound_endpoints(
    request: &AuthorizationRequestObject,
    identifier: &CanonicalDnsName,
) -> Result<(), WalletError> {
    for endpoint in [
        request.response_uri.as_deref(),
        request.redirect_uri.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let parsed = parse_endpoint(endpoint)?;
        if !parsed.host_matches_dns_name(identifier) {
            return Err(WalletError::new(
                WalletErrorReason::ResponseEndpointClientIdentifierMismatch,
            ));
        }
    }
    Ok(())
}

fn validate_endpoint_shapes(request: &AuthorizationRequestObject) -> Result<(), WalletError> {
    for endpoint in [
        request.response_uri.as_deref(),
        request.redirect_uri.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let _validated = parse_endpoint(endpoint)?;
    }
    Ok(())
}

fn parse_endpoint(endpoint: &str) -> Result<ValidatedHttpsEndpoint, WalletError> {
    // RFC 3986 Sections 3.2 and 6.2 provide the authority and normalization
    // model. The shared type adds this wallet's fail-closed HTTPS policy.
    ValidatedHttpsEndpoint::parse(endpoint)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))
}
