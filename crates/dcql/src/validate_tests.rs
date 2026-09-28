// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::json;

use crate::{ClaimQuery, ClaimsPath, ClaimsPathComponent, CredentialQuery, CredentialSetQuery};

use super::{
    validate_query, JsonMap, MAX_CLAIMS_PATH_COMPONENTS, MAX_CREDENTIAL_SETS,
    MAX_CREDENTIAL_SET_REFERENCES,
};
use crate::{CredentialFormat, DcqlError, DcqlErrorReason, DcqlQuery, QueryId};

#[test]
fn rejects_over_deep_claim_path() -> Result<(), DcqlError> {
    let mut query = valid_query()?;
    query.credentials[0].claims = Some(vec![ClaimQuery {
        id: None,
        path: ClaimsPath(vec![
            ClaimsPathComponent::Name("nested".to_owned());
            MAX_CLAIMS_PATH_COMPONENTS + 1
        ]),
        values: None,
        intent_to_retain: None,
    }]);

    assert_eq!(
        validate_query(&query).map_err(DcqlError::reason),
        Err(DcqlErrorReason::QueryTooLarge)
    );
    Ok(())
}

#[test]
fn rejects_too_many_credential_sets() -> Result<(), DcqlError> {
    let mut query = valid_query()?;
    query.credential_sets = Some(vec![credential_set()?; MAX_CREDENTIAL_SETS + 1]);

    assert_eq!(
        validate_query(&query).map_err(DcqlError::reason),
        Err(DcqlErrorReason::QueryTooLarge)
    );
    Ok(())
}

#[test]
fn rejects_too_many_credential_set_references() -> Result<(), DcqlError> {
    let mut query = valid_query()?;
    query.credential_sets = Some(vec![CredentialSetQuery {
        options: vec![vec![QueryId::parse("pid")?]; MAX_CREDENTIAL_SET_REFERENCES + 1],
        required: true,
    }]);

    assert_eq!(
        validate_query(&query).map_err(DcqlError::reason),
        Err(DcqlErrorReason::QueryTooLarge)
    );
    Ok(())
}

#[test]
fn rejects_claim_without_id_when_claim_sets_are_present() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{"path": ["given_name"]}],
            "claim_sets": [["given_name"]]
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::MissingClaimIdentifier)
    );
}

#[test]
fn accepts_claim_without_id_when_claim_sets_are_absent() -> Result<(), DcqlError> {
    let mut query = valid_query()?;
    query.credentials[0].claims = Some(vec![ClaimQuery {
        id: None,
        path: ClaimsPath(vec![ClaimsPathComponent::Name("given_name".to_owned())]),
        values: None,
        intent_to_retain: None,
    }]);

    validate_query(&query)
}

#[test]
fn rejects_claim_sets_without_claims() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claim_sets": [["given_name"]]
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::ClaimSetsWithoutClaims)
    );
}

#[test]
fn rejects_duplicate_claim_identifiers() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [
              {"id": "name", "path": ["given_name"]},
              {"id": "name", "path": ["family_name"]}
            ],
            "claim_sets": [["name"]]
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::DuplicateIdentifier)
    );
}

#[test]
fn rejects_unregistered_trusted_authority_type() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "trusted_authorities": [{
              "type": "unregistered_authority",
              "values": ["authority-1"]
            }]
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::UnsupportedTrustedAuthorityType)
    );
}

#[test]
fn accepts_every_registered_trusted_authority_type() -> Result<(), DcqlError> {
    for authority_type in ["aki", "etsi_tl", "openid_federation"] {
        let mut query = valid_query()?;
        query.credentials[0].trusted_authorities = Some(vec![crate::TrustedAuthorityQuery {
            authority_type: authority_type.to_owned(),
            values: vec!["authority-1".to_owned()],
        }]);

        validate_query(&query)?;
    }
    Ok(())
}

#[test]
fn rejects_mixed_or_empty_sd_jwt_vct_values() {
    for vct_values in [r#"["urn:eudi:pid:1", 7]"#, r#"[""]"#] {
        let query = format!(
            r#"{{
              "credentials": [{{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {{"vct_values": {vct_values}}}
              }}]
            }}"#
        );
        let result = DcqlQuery::from_json_slice(query.as_bytes());
        assert_eq!(
            result.map(|_| ()).map_err(DcqlError::reason),
            Err(DcqlErrorReason::InvalidCredentialMetadata)
        );
    }
}

#[test]
fn ignores_unknown_supported_format_metadata() -> Result<(), DcqlError> {
    let sd_jwt = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {
              "vct_values": ["urn:eudi:pid:1"],
              "unexpected": true
            }
          }]
        }"#,
    )?;

    validate_query(&sd_jwt)?;

    let mdoc = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": {
              "doctype_value": "org.iso.18013.5.1.mDL",
              "future_extension": {"bounded": true}
            }
          }]
        }"#,
    )?;

    validate_query(&mdoc)
}

#[test]
fn rejects_empty_mdoc_doctype() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": {"doctype_value": ""}
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::InvalidCredentialMetadata)
    );
}

#[test]
fn rejects_non_iso_mdoc_claim_paths() {
    for path in [r#"["namespace"]"#, r#"["namespace", 0]"#] {
        let query = format!(
            r#"{{
              "credentials": [{{
                "id": "mdl",
                "format": "mso_mdoc",
                "meta": {{"doctype_value": "org.iso.18013.5.1.mDL"}},
                "claims": [{{"path": {path}}}]
              }}]
            }}"#
        );
        let result = DcqlQuery::from_json_slice(query.as_bytes());
        assert_eq!(
            result.map(|_| ()).map_err(DcqlError::reason),
            Err(DcqlErrorReason::InvalidClaimsPath)
        );
    }
}

#[test]
fn retains_mdoc_intent_to_retain() -> Result<(), DcqlError> {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{
              "path": ["org.iso.18013.5.1", "family_name"],
              "intent_to_retain": true
            }]
          }]
        }"#,
    )?;

    assert_eq!(
        query.credentials[0]
            .claims
            .as_ref()
            .and_then(|claims| { claims.first().and_then(|claim| claim.intent_to_retain) }),
        Some(true)
    );
    Ok(())
}

#[test]
fn leaves_absent_mdoc_retention_intent_unasserted() -> Result<(), DcqlError> {
    let query = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "mdl",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{
              "path": ["org.iso.18013.5.1", "family_name"]
            }]
          }]
        }"#,
    )?;

    assert_eq!(
        query.credentials[0]
            .claims
            .as_ref()
            .and_then(|claims| { claims.first().and_then(|claim| claim.intent_to_retain) }),
        None
    );
    Ok(())
}

#[test]
fn rejects_mdoc_retention_property_for_sd_jwt() {
    let result = DcqlQuery::from_json_slice(
        br#"{
          "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:eudi:pid:1"]},
            "claims": [{
              "path": ["family_name"],
              "intent_to_retain": false
            }]
          }]
        }"#,
    );

    assert_eq!(
        result.map(|_| ()).map_err(DcqlError::reason),
        Err(DcqlErrorReason::UnsupportedClaimProperty)
    );
}

#[test]
fn rejects_empty_json_claim_path_names_and_values() {
    for (claim, expected_reason) in [
        (r#"{"path": [""]}"#, DcqlErrorReason::InvalidClaimsPath),
        (
            r#"{"path": ["given_name"], "values": [""]}"#,
            DcqlErrorReason::InvalidClaimValue,
        ),
    ] {
        let query = format!(
            r#"{{
              "credentials": [{{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {{"vct_values": ["urn:eudi:pid:1"]}},
                "claims": [{claim}]
              }}]
            }}"#
        );
        let result = DcqlQuery::from_json_slice(query.as_bytes());
        assert_eq!(
            result.map(|_| ()).map_err(DcqlError::reason),
            Err(expected_reason)
        );
    }
}

fn valid_query() -> Result<DcqlQuery, DcqlError> {
    Ok(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid")?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
            multiple: false,
            meta: JsonMap::from_iter([(
                "vct_values".to_owned(),
                json!(["https://credentials.example.com/identity_credential"]),
            )]),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    })
}

fn credential_set() -> Result<CredentialSetQuery, DcqlError> {
    Ok(CredentialSetQuery {
        options: vec![vec![QueryId::parse("pid")?]],
        required: true,
    })
}
