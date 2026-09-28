// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use serde_json::json;

use crate::evaluate::{
    credential_satisfies_query, evaluate_query, CredentialCandidate, EvaluationCredential, JsonMap,
    SelectedClaims,
};
use crate::model::{CredentialFormat, DcqlQuery};
use crate::DcqlErrorReason;

fn sd_jwt_format() -> CredentialFormat {
    CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).expect("test format is valid")
}

fn candidate() -> CredentialCandidate {
    CredentialCandidate {
        id: EvaluationCredential::new("cred-1".to_owned()).expect("test id is valid"),
        format: sd_jwt_format(),
        meta: JsonMap::from_iter([(
            "vct_values".to_owned(),
            json!(["https://credentials.example.com/identity_credential"]),
        )]),
        claims: json!({
            "first_name": "Ada",
            "last_name": "Lovelace",
            "age_over_18": true,
            "address": {
                "postal_code": "SW1A"
            }
        }),
        cryptographic_holder_binding: true,
    }
}

#[test]
fn evaluates_required_query_with_selected_claims() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
              {"id": "given", "path": ["first_name"], "values": ["Ada"]},
              {"id": "family", "path": ["last_name"]}
            ]
          }]
        }"#,
    )
    .expect("test query is valid");

    let evaluation = evaluate_query(&query, &[candidate()]).expect("query is satisfiable");

    assert_eq!(evaluation.matches.len(), 1);
    assert_eq!(evaluation.matches[0].query_id.as_str(), "pid");
    assert_eq!(
        evaluation.matches[0].credentials[0].credential_id.as_str(),
        "cred-1"
    );
    assert_eq!(
        evaluation.matches[0].credentials[0].claims,
        SelectedClaims::AllRequired
    );
}

#[test]
fn evaluates_query_without_claims_as_a_matching_credential() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            }
          }]
        }"#,
    )
    .expect("test query is valid");

    let evaluation = evaluate_query(&query, &[candidate()]).expect("query is satisfiable");

    assert_eq!(evaluation.matches.len(), 1);
    assert_eq!(evaluation.matches[0].credentials.len(), 1);
    assert_eq!(
        evaluation.matches[0].credentials[0].claims,
        SelectedClaims::NoClaimsRequested
    );
}

#[test]
fn query_without_claims_still_enforces_credential_metadata() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            }
          }]
        }"#,
    )
    .expect("test query is valid");
    let mut non_matching = candidate();
    non_matching.meta.insert(
        "vct_values".to_owned(),
        json!(["https://credentials.example.com/address_credential"]),
    );

    let error = evaluate_query(&query, &[non_matching])
        .expect_err("omitting claims must not bypass credential metadata matching");

    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn malformed_candidate_metadata_fails_closed_before_matching() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:example:allowed"]}
          }]
        }"#,
    )
    .expect("test query is valid");
    let mut malformed = candidate();
    malformed
        .meta
        .insert("vct_values".to_owned(), json!(["urn:example:allowed", 7]));

    let error = evaluate_query(&query, &[malformed])
        .expect_err("a later malformed metadata item must invalidate the whole candidate array");

    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn rejects_trusted_authorities_without_authenticated_authority_evidence() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "trusted_authorities": [{"type":"aki","values":["spoofed"]}]
          }]
        }"#,
    )
    .expect("registered authority query is structurally valid");
    let mut unauthenticated = candidate();
    unauthenticated
        .meta
        .insert("aki".to_owned(), json!("spoofed"));

    let verifier_match = credential_satisfies_query(&query.credentials[0], &unauthenticated)
        .expect("matching returns a typed result");
    assert!(!verifier_match);
    let error = evaluate_query(&query, &[unauthenticated])
        .expect_err("wallet selection must apply the same fail-closed authority policy");
    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn requires_every_claim_when_claim_sets_are_absent() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
              {"id": "given", "path": ["first_name"]},
              {"id": "missing", "path": ["missing_claim"]}
            ]
          }]
        }"#,
    )
    .expect("test query is valid");

    let error = evaluate_query(&query, &[candidate()])
        .expect_err("all listed claims are required without claim_sets");

    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn claim_sets_select_verifier_preferred_satisfied_option() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
              {"id": "given", "path": ["first_name"]},
              {"id": "postal", "path": ["address", "postal_code"]},
              {"id": "adult", "path": ["age_over_18"], "values": [true]}
            ],
            "claim_sets": [
              ["given", "postal"],
              ["adult"]
            ]
          }]
        }"#,
    )
    .expect("test query is valid");

    let evaluation = evaluate_query(&query, &[candidate()]).expect("query is satisfiable");
    assert!(matches!(
        &evaluation.matches[0].credentials[0].claims,
        SelectedClaims::ClaimSet(_)
    ));
    let SelectedClaims::ClaimSet(selected) = &evaluation.matches[0].credentials[0].claims else {
        return;
    };
    assert_eq!(selected.len(), 2);
    assert_eq!(selected[0].as_str(), "given");
    assert_eq!(selected[1].as_str(), "postal");
}

#[test]
fn multiple_credentials_retain_independent_claim_set_selections() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "multiple": true,
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
              {"id": "name", "path": ["first_name"], "values": ["Ada"]},
              {"id": "adult", "path": ["age_over_18"], "values": [true]}
            ],
            "claim_sets": [["name"], ["adult"]]
          }]
        }"#,
    )
    .expect("test query is valid");
    let mut name_credential = candidate();
    name_credential.claims = json!({"first_name": "Ada", "age_over_18": false});
    let mut adult_credential = candidate();
    adult_credential.id = EvaluationCredential::new("cred-2".to_owned()).expect("test id is valid");
    adult_credential.claims = json!({"first_name": "Grace", "age_over_18": true});

    let evaluation = evaluate_query(&query, &[name_credential, adult_credential])
        .expect("both credentials satisfy different alternatives");
    let selections = &evaluation.matches[0].credentials;
    assert_eq!(selections.len(), 2);
    assert_eq!(
        selections[0].claims,
        SelectedClaims::ClaimSet(vec![
            crate::QueryId::parse("name").expect("test id is valid")
        ])
    );
    assert_eq!(
        selections[1].claims,
        SelectedClaims::ClaimSet(vec![
            crate::QueryId::parse("adult").expect("test id is valid")
        ])
    );
}

#[test]
fn rejects_credential_when_no_claim_set_is_satisfiable() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [
              {"id": "wrong_name", "path": ["first_name"], "values": ["Grace"]},
              {"id": "wrong_age", "path": ["age_over_18"], "values": [false]}
            ],
            "claim_sets": [
              ["wrong_name"],
              ["wrong_age"]
            ]
          }]
        }"#,
    )
    .expect("test query is valid");

    let error = evaluate_query(&query, &[candidate()])
        .expect_err("a credential satisfying no claim-set option must be rejected");

    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn rejects_duplicate_query_ids() {
    let error = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}},
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}}
          ]
        }"#,
    )
    .expect_err("duplicate ids must be rejected");

    assert_eq!(error.reason(), DcqlErrorReason::DuplicateIdentifier);
}

#[test]
fn enforces_required_credential_sets() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}},
            {"id": "address", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/address_credential"]}}
          ],
          "credential_sets": [{
            "options": [["pid", "address"]]
          }]
        }"#,
    )
    .expect("test query is structurally valid");

    let error = evaluate_query(&query, &[candidate()])
        .expect_err("required credential set must not be partially satisfiable");

    assert_eq!(
        error.reason(),
        DcqlErrorReason::UnsatisfiedRequiredCredential
    );
}

#[test]
fn ignores_an_unsatisfied_optional_credential_set() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [
            {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/identity_credential"]}},
            {"id": "address", "format": "dc+sd-jwt", "meta": {"vct_values": ["https://credentials.example.com/address_credential"]}}
          ],
          "credential_sets": [
            {"options": [["pid"]]},
            {"options": [["address"]], "required": false}
          ]
        }"#,
    )
    .expect("test query is structurally valid");

    let evaluation = evaluate_query(&query, &[candidate()])
        .expect("an unsatisfied optional credential set must not fail the request");

    assert_eq!(evaluation.matches[0].credentials.len(), 1);
    assert!(evaluation.matches[1].credentials.is_empty());
}

#[test]
fn wildcard_expansion_is_charged_to_the_runtime_work_budget() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "multiple": true,
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [{"path": ["items", null]}]
          }]
        }"#,
    )
    .expect("wildcard query is structurally valid");
    let claims = json!({"items": vec![serde_json::Value::Null; 4_096]});
    let candidates = (0..250)
        .map(|index| {
            let mut value = candidate();
            value.id =
                EvaluationCredential::new(format!("cred-{index}")).expect("test id is valid");
            value.claims = claims.clone();
            value
        })
        .collect::<Vec<_>>();

    let error = evaluate_query(&query, &candidates)
        .expect_err("actual wildcard node visits must exhaust the shared work budget");

    assert_eq!(error.reason(), DcqlErrorReason::QueryTooLarge);
}

#[test]
fn every_candidate_value_comparison_is_charged_to_the_work_budget() {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "multiple": true,
            "meta": {
              "vct_values": ["https://credentials.example.com/identity_credential"]
            },
            "claims": [{
              "path": ["items", null],
              "values": ["a", "b", "c", "d", "e"]
            }]
          }]
        }"#,
    )
    .expect("test query is structurally valid");
    let claims = json!({"items": vec!["not-a-match"; 2_000]});
    let candidates = (0..100)
        .map(|index| {
            let mut value = candidate();
            value.id =
                EvaluationCredential::new(format!("cred-{index}")).expect("test id is valid");
            value.claims = claims.clone();
            value
        })
        .collect::<Vec<_>>();

    let error = evaluate_query(&query, &candidates)
        .expect_err("nested candidate-value comparisons must exhaust the shared work budget");

    assert_eq!(error.reason(), DcqlErrorReason::QueryTooLarge);
}

#[test]
fn every_candidate_metadata_comparison_is_charged_to_the_work_budget() {
    let mut query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:example:initial"]}
          }]
        }"#,
    )
    .expect("test query is structurally valid");
    let allowed_values = (0..128)
        .map(|index| json!(format!("urn:example:allowed:{index}")))
        .collect();
    query.credentials[0].meta.insert(
        "vct_values".to_owned(),
        serde_json::Value::Array(allowed_values),
    );

    let mut non_matching = candidate();
    non_matching.meta.insert(
        "vct_values".to_owned(),
        json!(vec!["urn:example:not-allowed"; 8_000]),
    );

    let error = evaluate_query(&query, &[non_matching])
        .expect_err("nested candidate metadata comparisons must exhaust the shared work budget");

    assert_eq!(error.reason(), DcqlErrorReason::QueryTooLarge);
}
