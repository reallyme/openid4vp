// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::client_id::{ClientIdentifier, ClientIdentifierPrefix};
use zeroize::Zeroize;

#[test]
fn parses_final_spec_prefix() {
    let mut parsed = ClientIdentifier::parse("x509_san_dns:client.example.org")
        .expect("test client identifier is valid");

    assert_eq!(parsed.prefix(), ClientIdentifierPrefix::X509SanDns);
    assert_eq!(parsed.identifier(), "client.example.org");
    assert_eq!(parsed.to_wire_value(), "x509_san_dns:client.example.org");
    assert!(!format!("{parsed:?}").contains("client.example.org"));

    parsed.zeroize();
    assert!(parsed.identifier().is_empty());
}

#[test]
fn rejects_unknown_prefix_like_identifier() {
    let err = ClientIdentifier::parse("https://client.example.org")
        .expect_err("colon-bearing unknown prefixes fail closed");

    assert_eq!(
        err.reason(),
        crate::OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix
    );
}
