// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::{ClientIdentifier, TransactionDataHashAlgorithm};
use zeroize::Zeroize;

use crate::holder_binding::{
    validate_holder_binding_claims, validate_holder_binding_claims_for_query,
};
use crate::{HolderBindingClaims, RequestBinding, TransactionDataBinding, VerifierErrorReason};

fn binding() -> RequestBinding {
    RequestBinding {
        client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
            .expect("test client id is valid"),
        nonce: "0123456789abcdef".to_owned(),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        dc_api_origin: None,
        expiry_unix: 100,
        transaction_data_bindings: Vec::new(),
    }
}

#[test]
fn accepts_matching_holder_binding_claims() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    validate_holder_binding_claims(&binding(), &claims, 10)
        .expect("matching holder binding claims validate");
}

#[test]
fn accepts_holder_binding_without_expiration() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 0,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    validate_holder_binding_claims(&binding(), &claims, 10)
        .expect("standard KB-JWT without exp validates when nonce and aud bind");
}

#[test]
fn deserializes_string_audience() {
    let claims: HolderBindingClaims = serde_json::from_str(
        r#"{"audience":"x509_san_dns:verifier.example","nonce":"0123456789abcdef","expiration_unix":0}"#,
    )
    .expect("string audience deserializes");

    assert_eq!(claims.audience, vec!["x509_san_dns:verifier.example"]);
}

#[test]
fn holder_binding_claims_redact_and_zeroize_sensitive_values() {
    let mut claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 0,
        issued_at_unix: 10,
        sd_hash: Some("sensitive-holder-binding-hash".to_owned()),
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    assert_eq!(claims.audience, vec!["x509_san_dns:verifier.example"]);
    assert_eq!(claims.nonce, "0123456789abcdef");
    assert_eq!(claims.expiration_unix, 0);
    assert_eq!(claims.issued_at_unix, 10);
    assert_eq!(
        claims.sd_hash.as_deref(),
        Some("sensitive-holder-binding-hash")
    );
    let debug = format!("{claims:?}");
    assert!(!debug.contains("sensitive-holder-binding-hash"));
    assert!(!debug.contains("verifier.example"));

    claims.zeroize();
    assert!(claims.audience.is_empty());
    assert!(claims.nonce.is_empty());
    assert!(claims.sd_hash.is_none());
}

#[test]
fn rejects_holder_binding_expiring_after_request() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 101,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    let err = validate_holder_binding_claims(&binding(), &claims, 10)
        .expect_err("holder binding must not outlive request binding");

    assert_eq!(err.reason(), VerifierErrorReason::HolderBindingExpired);
}

#[test]
fn rejects_holder_binding_with_wrong_audience() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:other.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    let err = validate_holder_binding_claims(&binding(), &claims, 10)
        .expect_err("audience must bind to the verifier client identifier");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::HolderBindingAudienceMismatch
    );
}

#[test]
fn signed_dc_api_holder_binding_uses_the_invoking_origin() {
    let mut dc_api_binding = binding();
    dc_api_binding.response_uri = None;
    dc_api_binding.dc_api_origin = Some("https://wallet.example".to_owned());
    let matching = HolderBindingClaims {
        audience: vec!["origin:https://wallet.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };
    validate_holder_binding_claims(&dc_api_binding, &matching, 10)
        .expect("signed DC API uses the invoking browser origin");

    let mut wrong = matching;
    wrong.audience = vec!["x509_san_dns:verifier.example".to_owned()];
    let error = validate_holder_binding_claims(&dc_api_binding, &wrong, 10)
        .expect_err("the request client identifier cannot replace the DC API origin");
    assert_eq!(
        error.reason(),
        VerifierErrorReason::HolderBindingAudienceMismatch
    );
}

#[test]
fn rejects_holder_binding_with_wrong_nonce() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "other-nonce".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    let err = validate_holder_binding_claims(&binding(), &claims, 10)
        .expect_err("nonce must bind to the verifier request");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::HolderBindingNonceMismatch
    );
}

#[test]
fn rejects_holder_binding_expired_before_validation() {
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 10,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: Vec::new(),
        transaction_data_hashes_alg: None,
    };

    let err = validate_holder_binding_claims(&binding(), &claims, 10)
        .expect_err("expired holder binding proof is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::HolderBindingExpired);
}

#[test]
fn validates_transaction_data_only_from_verified_holder_claims() {
    let mut bound = binding();
    let pid = QueryId::parse("pid").expect("test query id is valid");
    bound.transaction_data_bindings = vec![
        TransactionDataBinding {
            query_id: pid.clone(),
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest: [7; 32],
        },
        TransactionDataBinding {
            query_id: pid.clone(),
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest: [8; 32],
        },
    ];
    let claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: vec![[7; 32], [8; 32]],
        transaction_data_hashes_alg: Some(TransactionDataHashAlgorithm::Sha256),
    };

    validate_holder_binding_claims_for_query(&bound, Some(&pid), &claims, 10)
        .expect("the verified holder proof contains every ordered requested digest");

    let mut missing_algorithm = claims.clone();
    missing_algorithm.transaction_data_hashes_alg = None;
    validate_holder_binding_claims_for_query(&bound, Some(&pid), &missing_algorithm, 10)
        .expect("an omitted algorithm uses the OpenID4VP SHA-256 default");

    let mut extra_digest = claims.clone();
    extra_digest.transaction_data_hashes.push([9; 32]);
    let error = validate_holder_binding_claims_for_query(&bound, Some(&pid), &extra_digest, 10)
        .expect_err("extra signed digests must not be smuggled past a single-value request");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);

    let mut wrong = claims;
    wrong.transaction_data_hashes = vec![[8; 32], [7; 32]];
    let error = validate_holder_binding_claims_for_query(&bound, Some(&pid), &wrong, 10)
        .expect_err("changing transaction-data order must fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}

#[test]
fn preserves_duplicate_transaction_data_and_rejects_cross_query_substitution() {
    let mut bound = binding();
    let pid = QueryId::parse("pid").expect("test query id is valid");
    let address = QueryId::parse("address").expect("test query id is valid");
    bound.transaction_data_bindings = vec![
        TransactionDataBinding {
            query_id: pid.clone(),
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest: [7; 32],
        },
        TransactionDataBinding {
            query_id: pid.clone(),
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest: [7; 32],
        },
        TransactionDataBinding {
            query_id: address,
            algorithm: TransactionDataHashAlgorithm::Sha256,
            digest: [9; 32],
        },
    ];
    let mut claims = HolderBindingClaims {
        audience: vec!["x509_san_dns:verifier.example".to_owned()],
        nonce: "0123456789abcdef".to_owned(),
        expiration_unix: 90,
        issued_at_unix: 10,
        sd_hash: None,
        transaction_data_hashes: vec![[7; 32], [7; 32]],
        transaction_data_hashes_alg: None,
    };

    validate_holder_binding_claims_for_query(&bound, Some(&pid), &claims, 10)
        .expect("duplicate transaction objects remain significant and ordered");

    claims.transaction_data_hashes = vec![[7; 32], [9; 32]];
    let error = validate_holder_binding_claims_for_query(&bound, Some(&pid), &claims, 10)
        .expect_err("a digest bound to another credential query must not substitute");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
}
