// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{CanonicalDnsName, CanonicalEndpointHost, ValidatedHttpsEndpoint};

#[test]
fn canonicalizes_idna_and_dns_case() {
    let unicode =
        CanonicalDnsName::parse_reference("BÜCHER.example").expect("valid IDN reference name");
    let a_label =
        CanonicalDnsName::parse_rfc5280_san("xn--bcher-kva.example").expect("valid A-label SAN");
    assert_eq!(unicode, a_label);
}

#[test]
fn rejects_wildcard_and_trailing_dot_sans() {
    assert!(CanonicalDnsName::parse_rfc5280_san("*.example.org").is_err());
    assert!(CanonicalDnsName::parse_rfc5280_san("verifier.example.org.").is_err());
    assert!(CanonicalDnsName::parse_rfc5280_san("bad_label.example.org").is_err());
    assert!(CanonicalDnsName::parse_rfc5280_san("-bad.example.org").is_err());
    assert!(CanonicalDnsName::parse_rfc5280_san("xn--a.example.org").is_err());
}

#[test]
fn parses_ipv6_semantically() {
    let compressed = ValidatedHttpsEndpoint::parse("https://[2001:db8::1]/response")
        .expect("valid compressed IPv6 endpoint");
    let expanded =
        ValidatedHttpsEndpoint::parse("https://[2001:0db8:0000:0000:0000:0000:0000:0001]/response")
            .expect("valid expanded IPv6 endpoint");
    assert_eq!(compressed.host(), expanded.host());
    assert!(matches!(compressed.host(), CanonicalEndpointHost::Ipv6(_)));
}

#[test]
fn rejects_ambiguous_or_unsafe_https_authorities() {
    for value in [
        "http://verifier.example/response",
        "https://user@verifier.example/response",
        "https://@verifier.example/response",
        "https://verifier.example\\response",
        "https://verifier.example\\@attacker.example/response",
        "https://verifier.example/response#fragment",
        "https://verifier%2eexample/response",
        " https://verifier.example/response",
        "https://verifier.example./response",
    ] {
        assert!(
            ValidatedHttpsEndpoint::parse(value).is_err(),
            "unsafe endpoint accepted"
        );
    }
}
