// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Executes machine-readable conformance vectors against the implementation.

#![allow(clippy::expect_used)]

use reallyme_openid4vp_conformance::{
    parse_vectors, run_vector, ConformanceError, ConformanceResult, ConformanceVector,
    ExpectedResult, VectorOutcome,
};
use reallyme_openid4vp_types::{CanonicalDnsName, ValidatedHttpsEndpoint};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const MALICIOUS_JSON_VECTORS: &str = include_str!("../../vectors/openid4vp-malicious-json.json");
const X509_BINDING_VECTORS: &str =
    include_str!("../../vectors/openid4vp-x509-request-binding.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X509BindingVectors {
    schema: String,
    normative_basis: Vec<String>,
    policy_version: u32,
    hash_cases: Vec<X509HashCase>,
    dns_cases: Vec<X509DnsCase>,
    endpoint_cases: Vec<EndpointCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X509HashCase {
    id: String,
    leaf_der_base64: String,
    client_identifier: String,
    matches: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct X509DnsCase {
    id: String,
    client_identifier: String,
    dns_san: String,
    matches: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointCase {
    id: String,
    endpoint: String,
    dns_name: String,
    matches: bool,
}

#[test]
fn malicious_json_vectors_match_implementation_behavior() -> ConformanceResult<()> {
    let vectors = parse_vectors(MALICIOUS_JSON_VECTORS)?;
    assert!(
        !vectors.is_empty(),
        "expected at least one conformance vector"
    );

    for vector in &vectors {
        let outcome = run_vector(vector)?;
        assert_eq!(
            outcome,
            VectorOutcome::Passed,
            "vector {} ({}) did not behave as expected: {outcome:?}",
            vector.id,
            vector.spec_section
        );
    }
    Ok(())
}

#[test]
fn x509_request_binding_vectors_match_implementation() {
    let vectors: X509BindingVectors =
        serde_json::from_str(X509_BINDING_VECTORS).expect("reviewed X.509 vectors parse");
    assert_eq!(
        vectors.schema,
        "reallyme.openid4vp.x509_request_binding_vectors.v1"
    );
    assert_eq!(vectors.policy_version, 1);
    assert!(vectors.normative_basis.len() >= 4);

    for case in vectors.hash_cases {
        let leaf_der = reallyme_codec::base64::base64_to_bytes(&case.leaf_der_base64)
            .expect("reviewed leaf DER base64");
        let actual = reallyme_codec::base64url::bytes_to_base64url(&Sha256::digest(leaf_der));
        assert_eq!(
            actual == case.client_identifier,
            case.matches,
            "{}",
            case.id
        );
    }

    for case in vectors.dns_cases {
        let reference = CanonicalDnsName::parse_reference(&case.client_identifier);
        let san = CanonicalDnsName::parse_rfc5280_san(&case.dns_san);
        let actual = matches!((reference, san), (Ok(reference), Ok(san)) if reference == san);
        assert_eq!(actual, case.matches, "{}", case.id);
    }

    for case in vectors.endpoint_cases {
        let endpoint = ValidatedHttpsEndpoint::parse(&case.endpoint);
        let dns_name = CanonicalDnsName::parse_reference(&case.dns_name);
        let actual = matches!(
            (endpoint, dns_name),
            (Ok(endpoint), Ok(dns_name)) if endpoint.host_matches_dns_name(&dns_name)
        );
        assert_eq!(actual, case.matches, "{}", case.id);
    }
}

#[test]
fn unknown_target_fails_loudly() {
    let vector = ConformanceVector {
        id: "unknown".to_owned(),
        spec_section: "n/a".to_owned(),
        target: "types::DoesNotExist".to_owned(),
        input: "{}".to_owned(),
        expected: ExpectedResult::Reject,
    };
    assert_eq!(run_vector(&vector), Err(ConformanceError::UnknownTarget));
}

#[test]
fn accept_expectation_is_enforced() -> ConformanceResult<()> {
    let vector = ConformanceVector {
        id: "accept-dcql-query".to_owned(),
        spec_section: "OpenID4VP 1.0 Final DCQL".to_owned(),
        target: "dcql::DcqlQuery".to_owned(),
        input: r#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]}}]}"#.to_owned(),
        expected: ExpectedResult::Accept,
    };
    assert_eq!(run_vector(&vector)?, VectorOutcome::Passed);
    Ok(())
}
