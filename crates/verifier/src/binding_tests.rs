// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::ClientIdentifier;
use zeroize::Zeroize;

use crate::binding::validate_request_binding;
use crate::{RequestBinding, VerifierErrorReason};

fn binding() -> RequestBinding {
    RequestBinding {
        client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
            .expect("test client id is valid"),
        nonce: "0123456789abcdef".to_owned(),
        response_uri: Some("https://verifier.example/response?session=1".to_owned()),
        redirect_uri: None,
        dc_api_origin: None,
        expiry_unix: 100,
        transaction_data_bindings: Vec::new(),
    }
}

#[test]
fn accepts_https_response_uri_with_query() {
    let mut binding = binding();
    validate_request_binding(&binding, 10).expect("https response_uri is valid");

    let debug = format!("{binding:?}");
    assert!(!debug.contains("session=1"));
    assert!(!debug.contains("0123456789abcdef"));

    binding.zeroize();
    assert!(binding.nonce.is_empty());
    assert!(binding.response_uri.is_none());
}

#[test]
fn rejects_binding_at_expiry_boundary() {
    let binding = binding();

    let error = validate_request_binding(&binding, binding.expiry_unix)
        .expect_err("expiry is an exclusive upper bound");

    assert_eq!(error.reason(), VerifierErrorReason::BindingExpired);
}

#[test]
fn rejects_unavailable_clock_before_response_validation() {
    let binding = binding();

    let error = validate_request_binding(&binding, 0)
        .expect_err("zero cannot represent a trusted verification time");

    assert_eq!(error.reason(), VerifierErrorReason::ClockUnavailable);
}

#[test]
fn rejects_short_session_nonce() {
    let mut binding = binding();
    binding.nonce = "1".to_owned();

    let error = validate_request_binding(&binding, 10)
        .expect_err("trivially guessable nonce must be rejected");

    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn rejects_missing_response_and_redirect_uri() {
    let mut binding = binding();
    binding.response_uri = None;

    let err =
        validate_request_binding(&binding, 10).expect_err("one response endpoint is required");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn accepts_canonical_dc_api_origin_without_http_response_endpoint() {
    let mut binding = binding();
    binding.response_uri = None;
    binding.dc_api_origin = Some("https://wallet.example".to_owned());

    validate_request_binding(&binding, 10).expect("DC API origin is a complete binding variant");
}

#[test]
fn rejects_ambiguous_or_non_https_dc_api_origins() {
    for origin in [
        "http://wallet.example",
        "https://user@wallet.example",
        "https://wallet.example/path",
        "https://wallet.example?query=1",
    ] {
        let mut binding = binding();
        binding.response_uri = None;
        binding.dc_api_origin = Some(origin.to_owned());
        let error = validate_request_binding(&binding, 10)
            .expect_err("malformed DC API origins fail closed");
        assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
    }

    let mut ambiguous = binding();
    ambiguous.dc_api_origin = Some("https://wallet.example".to_owned());
    let error = validate_request_binding(&ambiguous, 10)
        .expect_err("DC API origin and HTTP endpoint cannot be mixed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn rejects_non_https_response_uri() {
    let mut binding = binding();
    binding.response_uri = Some("http://verifier.example/response".to_owned());

    let err =
        validate_request_binding(&binding, 10).expect_err("non-HTTPS response_uri is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
}

#[test]
fn rejects_response_uri_with_fragment() {
    let mut binding = binding();
    binding.response_uri = Some("https://verifier.example/response#fragment".to_owned());

    let err =
        validate_request_binding(&binding, 10).expect_err("response_uri fragments are rejected");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
}

#[test]
fn rejects_response_uri_with_userinfo() {
    let mut binding = binding();
    binding.response_uri = Some("https://user@verifier.example/response".to_owned());

    let err =
        validate_request_binding(&binding, 10).expect_err("response_uri userinfo is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
}

#[test]
fn rejects_empty_response_uri_authority() {
    let mut binding = binding();
    binding.response_uri = Some("https:///response".to_owned());

    let err =
        validate_request_binding(&binding, 10).expect_err("response_uri authority is required");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
}

#[test]
fn accepts_x509_san_dns_response_uri_host_with_port() {
    let mut binding = binding();
    binding.response_uri = Some("https://verifier.example:8443/response".to_owned());

    validate_request_binding(&binding, 10).expect("response_uri host matches client_id");
}

#[test]
fn rejects_x509_san_dns_response_uri_host_mismatch() {
    let mut binding = binding();
    binding.response_uri = Some("https://attacker.example/response".to_owned());

    let err = validate_request_binding(&binding, 10)
        .expect_err("x509_san_dns response_uri host must match client_id");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn rejects_x509_san_dns_redirect_uri_host_mismatch() {
    let mut binding = binding();
    binding.response_uri = None;
    binding.redirect_uri = Some("https://attacker.example/cb".to_owned());

    let err = validate_request_binding(&binding, 10)
        .expect_err("x509_san_dns redirect_uri host must match client_id");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn accepts_idna_equivalent_x509_san_dns_endpoint_host() {
    let mut binding = binding();
    binding.client_id = ClientIdentifier::parse("x509_san_dns:bücher.example")
        .expect("test IDN client id is valid");
    binding.response_uri = Some("https://xn--bcher-kva.example/response".to_owned());

    validate_request_binding(&binding, 10).expect("IDNA-equivalent hosts match");
}

#[test]
fn rejects_percent_encoded_or_trailing_dot_endpoint_hosts() {
    for endpoint in [
        "https://verifier%2eexample/response",
        "https://verifier.example./response",
    ] {
        let mut binding = binding();
        binding.response_uri = Some(endpoint.to_owned());
        let err = validate_request_binding(&binding, 10)
            .expect_err("ambiguous endpoint authority is rejected");
        assert_eq!(err.reason(), VerifierErrorReason::InvalidRequestUri);
    }
}
