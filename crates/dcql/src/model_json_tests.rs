// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{DcqlQuery, MAX_DCQL_JSON_BYTES};
use crate::DcqlErrorReason;
use zeroize::Zeroize;

const VALID_QUERY: &[u8] = br#"{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example/pid"]}}]}"#;

#[test]
fn parses_valid_bounded_dcql_json() {
    let mut query = DcqlQuery::from_json_slice(VALID_QUERY).expect("valid DCQL parses");
    assert_eq!(query.credentials.len(), 1);

    let debug = format!("{query:?}");
    assert!(!debug.contains("credentials.example"));
    assert!(debug.contains("<redacted>"));

    query.zeroize();
    assert!(query.credentials.is_empty());
    assert!(query.credential_sets.is_none());
}

#[test]
fn rejects_oversized_dcql_json_before_parse() {
    let input = vec![b' '; MAX_DCQL_JSON_BYTES + 1];
    let error = DcqlQuery::from_json_slice(&input).expect_err("oversized DCQL is rejected");
    assert_eq!(error.reason(), DcqlErrorReason::QueryTooLarge);
}

#[test]
fn rejects_duplicate_dcql_json_members() {
    let input = br#"{"credentials":[],"credentials":[]}"#;
    let error = DcqlQuery::from_json_slice(input).expect_err("duplicate keys are rejected");
    assert_eq!(error.reason(), DcqlErrorReason::DuplicateJsonKey);
}

#[test]
fn rejects_trailing_dcql_json_data() {
    let mut input = VALID_QUERY.to_vec();
    input.extend_from_slice(b"{}");
    let error = DcqlQuery::from_json_slice(&input).expect_err("trailing JSON is rejected");
    assert_eq!(error.reason(), DcqlErrorReason::InvalidJson);
}

#[test]
fn ignores_unknown_properties_at_every_dcql_object_level() {
    let input = br#"{
      "future_top_level": {"bounded": true},
      "credentials": [{
        "id": "pid",
        "format": "dc+sd-jwt",
        "future_credential_member": 1,
        "meta": {
          "vct_values": ["https://credentials.example/pid"],
          "future_format_member": "ignored"
        },
        "trusted_authorities": [{
          "type": "aki",
          "values": ["authority"],
          "future_authority_member": false
        }],
        "claims": [{
          "id": "name",
          "path": ["name"],
          "future_claim_member": []
        }],
        "claim_sets": [["name"]]
      }],
      "credential_sets": [{
        "options": [["pid"]],
        "future_set_member": null
      }]
    }"#;

    let query = DcqlQuery::from_json_slice(input)
        .expect("bounded unknown properties are ignored by final DCQL processing");
    assert_eq!(query.credentials.len(), 1);
    assert_eq!(query.credential_sets.as_ref().map(Vec::len), Some(1));
}
