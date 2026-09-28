// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use crate::response::{
    diagnose_authorization_response, diagnose_authorization_response_with_options,
    validate_vp_token_query_coverage, ResponseValidationOptions,
};
use crate::{
    HolderBindingClaims, HolderBindingVerificationContext, HolderBindingVerifier, RequestBinding,
    SessionRecord, TransactionDataBinding, VerifiedDisclosureSet, VerifiedHolderBinding,
    VerifiedTrustProvenance, VerifierError, VerifierErrorReason,
};
use reallyme_openid4vp_dcql::{
    CredentialFormat, CredentialQuery, CredentialSetQuery, DcqlQuery, QueryId,
};
use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, encode_zk_presentation_value, ZkPresentation,
    ZkPresentationCircuitRef, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use reallyme_openid4vp_types::{AuthorizationResponse, ClientIdentifier, PresentationValue};

fn session() -> SessionRecord {
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: dcql_query(false),
        response_mode: reallyme_openid4vp_types::ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    }
}

fn dcql_query(multiple: bool) -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").expect("test query id is valid"),
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test format is valid"),
            multiple,
            meta: Default::default(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    }
}

#[test]
fn holder_binding_context_debug_redacts_session_material() {
    let active_session = session();
    let credential_query = &active_session.dcql_query.credentials[0];
    let context = HolderBindingVerificationContext::new(&active_session, credential_query, 10);

    let debug = format!("{context:?}");

    assert!(debug.contains("now_unix: 10"));
    assert!(debug.contains("dc+sd-jwt"));
    assert!(debug.contains("session: \"<redacted>\""));
    assert!(!debug.contains("0123456789abcdef"));
    assert!(!debug.contains("fedcba9876543210"));
}

struct FixtureHolderBindingVerifier;

impl HolderBindingVerifier for FixtureHolderBindingVerifier {
    fn verify_holder_binding(
        &self,
        _presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        if context.now_unix() != 10
            || context.session().binding.nonce != "0123456789abcdef"
            || context.credential_query().format.as_str() != CredentialFormat::DC_SD_JWT
            || context.credential_query().id.as_str() != "pid"
        {
            return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
        }
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec!["x509_san_dns:verifier.example".to_owned()],
                nonce: "0123456789abcdef".to_owned(),
                expiration_unix: 100,
                issued_at_unix: 10,
                sd_hash: None,
                transaction_data_hashes: context
                    .session()
                    .binding
                    .transaction_data_bindings
                    .iter()
                    .filter(|binding| binding.query_id == context.credential_query().id)
                    .map(|binding| binding.digest)
                    .collect(),
                transaction_data_hashes_alg: context
                    .session()
                    .binding
                    .transaction_data_bindings
                    .iter()
                    .any(|binding| binding.query_id == context.credential_query().id)
                    .then_some(TransactionDataHashAlgorithm::Sha256),
            },
            VerifiedDisclosureSet::Derived,
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}

struct RevokedCredentialVerifier;

impl HolderBindingVerifier for RevokedCredentialVerifier {
    fn verify_holder_binding(
        &self,
        _presentation: &PresentationValue,
        _context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        Err(VerifierError::new(VerifierErrorReason::CredentialRevoked))
    }
}

#[test]
fn accepts_response_matching_session() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    diagnose_authorization_response_with_options(
        &session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect("response matches session");
}

#[test]
fn rejects_credential_revocation_reported_by_format_verifier() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response_with_options(
        &session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&RevokedCredentialVerifier),
        },
    )
    .expect_err("revoked credential is rejected before claims are accepted");

    assert_eq!(err.reason(), VerifierErrorReason::CredentialRevoked);
}

#[test]
fn rejects_non_zk_presentation_without_holder_binding_verifier() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response(&session(), &response, 10)
        .expect_err("non-zk presentation requires holder-binding verifier");

    assert_eq!(err.reason(), VerifierErrorReason::UnsupportedFormat);
}

#[test]
fn rejects_state_mismatch() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("other".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response(&session(), &response, 10)
        .expect_err("state mismatch is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::SessionMismatch);
}

#[test]
fn rejects_empty_vp_token_object() {
    let response = AuthorizationResponse {
        vp_token: BTreeMap::new(),
        state: Some("fedcba9876543210".to_owned()),
    };

    let err = diagnose_authorization_response(&session(), &response, 10)
        .expect_err("empty vp_token object is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::EmptyVpToken);
}

#[test]
fn rejects_empty_presentation_list_for_query() {
    let mut vp_token = BTreeMap::new();
    vp_token.insert(
        QueryId::parse("pid").expect("test query id is valid"),
        Vec::new(),
    );
    let response = AuthorizationResponse {
        vp_token,
        state: Some("fedcba9876543210".to_owned()),
    };

    let err = diagnose_authorization_response(&session(), &response, 10)
        .expect_err("empty per-query presentation list is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::EmptyPresentationList);
}

#[test]
fn rejects_unknown_vp_token_query_id() {
    let response = AuthorizationResponse::single(
        QueryId::parse("other").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response_with_options(
        &session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect_err("response query ids must match session DCQL");

    assert_eq!(err.reason(), VerifierErrorReason::VpTokenQueryMismatch);
}

#[test]
fn accepts_one_complete_required_credential_set_alternative() {
    let mut session = session();
    let mut address = session.dcql_query.credentials[0].clone();
    address.id = QueryId::parse("address").expect("test query id is valid");
    let mut passport = session.dcql_query.credentials[0].clone();
    passport.id = QueryId::parse("passport").expect("test query id is valid");
    session.dcql_query.credentials.extend([address, passport]);
    session.dcql_query.credential_sets = Some(vec![CredentialSetQuery {
        options: vec![
            vec![
                QueryId::parse("pid").expect("test query id is valid"),
                QueryId::parse("address").expect("test query id is valid"),
            ],
            vec![QueryId::parse("passport").expect("test query id is valid")],
        ],
        required: true,
    }]);

    let passport_response = AuthorizationResponse::single(
        QueryId::parse("passport").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");
    validate_vp_token_query_coverage(&session, &passport_response)
        .expect("one complete required-set alternative is sufficient");

    let partial_response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");
    let error = validate_vp_token_query_coverage(&session, &partial_response)
        .expect_err("a partial required-set alternative must fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::VpTokenQueryMismatch);
}

#[test]
fn rejects_multiple_presentations_for_single_query() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![
            PresentationValue::Compact("presentation-one".to_owned()),
            PresentationValue::Compact("presentation-two".to_owned()),
        ],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response_with_options(
        &session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect_err("multiple:false query accepts one presentation");

    assert_eq!(
        err.reason(),
        VerifierErrorReason::VpTokenCardinalityMismatch
    );
}

#[test]
fn rejects_expired_request_binding_before_response_shape_checks() {
    let mut session = session();
    session.binding.expiry_unix = 9;
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let err = diagnose_authorization_response(&session, &response, 10)
        .expect_err("expired session binding is rejected");

    assert_eq!(err.reason(), VerifierErrorReason::BindingExpired);
}

fn zk_response() -> AuthorizationResponse {
    zk_response_for_binding(build_zk_presentation_binding(
        "0123456789abcdef",
        "x509_san_dns:verifier.example",
        None,
    ))
}

fn zk_response_for_binding(
    binding: reallyme_openid4vp_formats::ZkPresentationBinding,
) -> AuthorizationResponse {
    let stages = [
        (ZkPresentationStageKind::Session, "session"),
        (
            ZkPresentationStageKind::CredentialEnvelope,
            "credential_envelope",
        ),
        (ZkPresentationStageKind::CredentialRoot, "credential_root"),
        (ZkPresentationStageKind::Claim, "claim"),
    ]
    .into_iter()
    .enumerate()
    .map(|(index, (stage, stage_name))| ZkPresentationStage {
        stage,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: "sha256".to_owned(),
            family: "private_claim_v1".to_owned(),
            stage: stage_name.to_owned(),
            version: 1,
        },
        artifact_manifest_sha256: [41_u8; 32],
        proof: vec![u8::try_from(index).expect("four stages fit in u8") + 1],
        public_inputs: vec![7_u8; 32],
    })
    .collect();
    let presentation = ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::PrivateClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding,
    };
    AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![
            encode_zk_presentation_value(presentation).expect("valid test presentation serializes")
        ],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid")
}

fn transaction_bound_session() -> SessionRecord {
    let mut session = session();
    session.binding.transaction_data_bindings = vec![TransactionDataBinding {
        query_id: QueryId::parse("pid").expect("test query id is valid"),
        algorithm: TransactionDataHashAlgorithm::Sha256,
        digest: [3; 32],
    }];
    session
}

fn transaction_bound_zk_response() -> AuthorizationResponse {
    zk_response_for_binding(build_zk_presentation_binding(
        "0123456789abcdef",
        "x509_san_dns:verifier.example",
        Some([3; 32]),
    ))
}

#[test]
fn accepts_transaction_binding_extracted_from_verified_holder_proof() {
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    diagnose_authorization_response_with_options(
        &transaction_bound_session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect("the verified holder proof carries the transaction-data binding");
}

#[test]
fn rejects_zk_presentation_without_injected_format_verifier() {
    let err = diagnose_authorization_response(&session(), &zk_response(), 10)
        .expect_err("zk presentation requires an injected format verifier");

    assert_eq!(err.reason(), VerifierErrorReason::UnsupportedFormat);
}

#[test]
fn accepts_zk_presentation_from_injected_format_verifier() {
    diagnose_authorization_response_with_options(
        &session(),
        &zk_response(),
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect("a composed verifier can authorize a validated ZK presentation");
}

#[test]
fn accepts_transaction_bound_zk_from_injected_format_verifier() {
    diagnose_authorization_response_with_options(
        &transaction_bound_session(),
        &transaction_bound_zk_response(),
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect("verified claims carry the transaction-data binding");
}

#[test]
fn rejects_zk_binding_mismatch_before_format_verification() {
    let response = zk_response_for_binding(build_zk_presentation_binding(
        "different-nonce",
        "x509_san_dns:verifier.example",
        None,
    ));
    let err = diagnose_authorization_response_with_options(
        &session(),
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
        },
    )
    .expect_err("envelope replay is rejected before the format verifier runs");

    assert_eq!(err.reason(), VerifierErrorReason::InvalidZkPresentation);
}
