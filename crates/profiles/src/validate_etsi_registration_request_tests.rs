// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::DcqlQuery;
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ClientMetadata, ResponseMode, ResponseType,
    VerifierInfoEntry,
};
use serde_json::json;

use super::{validate_etsi_registration_request, EtsiRegistrationRequestErrorReason};

fn registrar_dataset() -> serde_json::Value {
    json!({
        "identifier": "rp.example",
        "srvDescription": [{"lang": "en", "content": "Example service"}],
        "registryURI": "https://registrar.example/api",
        "intendedUseIdentifier": "age-check",
        "purpose": [{"lang": "en", "content": "Age verification"}],
        "policyURI": "https://rp.example/privacy"
    })
}

fn entry(format: &str, data: serde_json::Value) -> VerifierInfoEntry {
    VerifierInfoEntry::try_new(format.to_owned(), data, None)
        .expect("test attestation is structurally valid")
}

fn request() -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_hash:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .expect("test client identifier parses"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPostJwt),
        response_uri: Some("https://rp.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: Vec::new(),
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: Some(ClientMetadata {
            raw: json!({"jwks": {"keys": [{"kid": "response-key", "use": "enc"}]}}),
        }),
        client_metadata_uri: None,
        verifier_info: Some(vec![entry("registrar_dataset", registrar_dataset())]),
        expected_origins: None,
        iss: None,
        aud: Some(vec!["wallet".to_owned()]),
        iat: None,
        exp: None,
    }
}

#[test]
fn accepts_registrar_dataset_without_registration_certificate() {
    let request = request();
    let checked = validate_etsi_registration_request(&request)
        .expect("the profile permits a registrar lookup without a WRPRC");
    assert!(checked.registration_certificate_b64url().is_none());
    assert_eq!(checked.registrar_identifier(), "rp.example");
    assert_eq!(checked.registry_uri(), "https://registrar.example/api");
    assert_eq!(checked.intended_use_identifier(), "age-check");
    assert_eq!(
        checked
            .registrar_dataset()
            .get("identifier")
            .and_then(serde_json::Value::as_str),
        Some("rp.example")
    );
}

#[test]
fn accepts_canonically_encoded_registration_certificate() {
    let mut request = request();
    request
        .verifier_info
        .as_mut()
        .expect("test verifier_info exists")
        .push(entry("registration_cert", json!("Y2VydGlmaWNhdGU")));
    let checked = validate_etsi_registration_request(&request)
        .expect("a bounded encoded credential is structurally valid");
    assert_eq!(
        checked.registration_certificate_b64url(),
        Some("Y2VydGlmaWNhdGU")
    );
}

#[test]
fn rejects_missing_or_ambiguous_registrar_data() {
    let mut missing = request();
    missing.verifier_info = None;
    assert_eq!(
        validate_etsi_registration_request(&missing)
            .err()
            .expect("registrar data is required")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
    );

    let mut duplicate = request();
    duplicate
        .verifier_info
        .as_mut()
        .expect("test verifier_info exists")
        .push(entry("registrar_dataset", registrar_dataset()));
    assert_eq!(
        validate_etsi_registration_request(&duplicate)
            .err()
            .expect("ambiguous registrar data is rejected")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
    );

    let mut malformed = request();
    malformed.verifier_info = Some(vec![entry(
        "registrar_dataset",
        json!({"identifier": "rp.example"}),
    )]);
    assert_eq!(
        validate_etsi_registration_request(&malformed)
            .err()
            .expect("missing registered purpose is rejected")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
    );
}

#[test]
fn rejects_unbound_profile_and_invalid_registration_encoding() {
    let mut wrong_client = request();
    wrong_client.client_id = Some(
        ClientIdentifier::parse("x509_san_dns:rp.example").expect("test client identifier parses"),
    );
    assert_eq!(
        validate_etsi_registration_request(&wrong_client)
            .err()
            .expect("ETSI requires x509_hash")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidClientIdentifier
    );

    let mut malformed = request();
    malformed
        .verifier_info
        .as_mut()
        .expect("test verifier_info exists")
        .push(entry("registration_cert", json!("not+base64url")));
    assert_eq!(
        validate_etsi_registration_request(&malformed)
            .err()
            .expect("noncanonical encoding is rejected")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidRegistrationCertificate
    );
}

#[test]
fn rejects_registrar_endpoint_with_unsafe_uri_syntax() {
    for uri in [
        "http://registrar.example/api",
        "https://user:secret@registrar.example/api",
        "https://registrar.example/api#fragment",
        "file:///registry",
    ] {
        let mut request = request();
        let mut dataset = registrar_dataset();
        dataset["registryURI"] = json!(uri);
        request.verifier_info = Some(vec![entry("registrar_dataset", dataset)]);
        assert_eq!(
            validate_etsi_registration_request(&request)
                .err()
                .expect("unsafe registrar URL must fail")
                .reason(),
            EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
        );
    }
}

#[test]
fn rejects_oversized_registrar_lookup_fields() {
    for (field, value) in [
        ("identifier", "a".repeat(513)),
        ("intendedUseIdentifier", "a".repeat(513)),
        (
            "registryURI",
            format!("https://registrar.example/{}", "a".repeat(2_048)),
        ),
    ] {
        let mut request = request();
        let mut dataset = registrar_dataset();
        dataset[field] = json!(value);
        request.verifier_info = Some(vec![entry("registrar_dataset", dataset)]);
        assert_eq!(
            validate_etsi_registration_request(&request)
                .err()
                .expect("oversized registrar field must fail")
                .reason(),
            EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
        );
    }
}

#[test]
fn rejects_credential_specific_registrar_data() {
    let mut request = request();
    request.verifier_info = Some(vec![VerifierInfoEntry::try_new(
        "registrar_dataset".to_owned(),
        registrar_dataset(),
        Some(vec!["pid".to_owned()]),
    )
    .expect("generic attestation permits a credential binding")]);
    assert_eq!(
        validate_etsi_registration_request(&request)
            .err()
            .expect("ETSI registrar data applies to the whole request")
            .reason(),
        EtsiRegistrationRequestErrorReason::InvalidRegistrarDataset
    );
}
