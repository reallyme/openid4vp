// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

//! Property coverage for OpenID4VP parser and generated-message boundaries.

use std::sync::{Arc, Mutex};

use proptest::collection::vec;
use proptest::prelude::{any, prop_assert, prop_assert_eq, proptest};
use proptest::sample::select;
use proptest::strategy::Strategy;
use proptest::test_runner::Config as ProptestConfig;
use reallyme_openid4vp_conformance::{
    run_vector, ConformanceVector, ExpectedResult, VectorOutcome,
};
use reallyme_openid4vp_dc_api::{DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest};
use reallyme_openid4vp_dcql::{
    evaluate_query, process_json_claims_path, ClaimQuery, ClaimSet, ClaimsPath,
    ClaimsPathComponent, CredentialCandidate, CredentialFormat, CredentialQuery, DcqlError,
    DcqlQuery, EvaluationCredential, QueryId,
};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_json_to_proto, authorization_request_proto_to_json,
    proto_to_authorization_response,
};
use reallyme_openid4vp_runtime::{
    HostedRequestObject, RequestObjectStore, ResponseCode, RuntimeClock, RuntimeError,
    RuntimeErrorReason, RuntimeHttpMethod, RuntimeHttpRequest, SessionReservation,
    VerifiedAuthorizationResponse, VerifierHttpEndpoint, VerifierHttpRuntime,
    VerifierRuntimeConfig, VerifierRuntimeService, VerifierSessionStore,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, PresentationValue, ResponseMode, ResponseType,
};
use reallyme_openid4vp_verifier::{
    BrowserSessionBinding, HolderBindingClaims, HolderBindingVerificationContext,
    HolderBindingVerifier, RequestBinding, SessionRecord, VerifiedDisclosureSet,
    VerifiedHolderBinding, VerifiedTrustProvenance, VerifierError,
};
use reallyme_openid4vp_wallet::{
    validate_verifier_attestation_binding, VerifiedVerifierAttestation,
};
use serde_json::{json, Map as JsonMap};

const PROPERTY_CASES: u32 = 128;
const MAX_TEST_QUERY_ID_BYTES: usize = 128;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPERTY_CASES))]

    #[test]
    fn query_id_acceptance_matches_identifier_rules(value in identifier_strategy()) {
        let parsed = QueryId::parse(&value);
        let valid = !value.is_empty()
            && value.len() <= MAX_TEST_QUERY_ID_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
            });
        prop_assert_eq!(parsed.is_ok(), valid);
    }

    #[test]
    fn dcql_claim_set_references_fail_closed(case in 0_u8..5) {
        let Ok(query) = dcql_query_for_claim_set_case(case) else {
            prop_assert!(false, "test fixture query must be constructible");
            return Ok(());
        };
        let valid = matches!(case, 0 | 3);
        prop_assert_eq!(reallyme_openid4vp_dcql::validate_query(&query).is_ok(), valid);
    }

    #[test]
    fn claims_path_selection_is_total(index in 0_u64..5, use_all in any::<bool>()) {
        let credential = json!({
            "names": [
                {"given_name": "Ada"},
                {"given_name": "Grace"}
            ]
        });
        let path = if use_all {
            ClaimsPath(vec![
                ClaimsPathComponent::Name("names".to_owned()),
                ClaimsPathComponent::All,
                ClaimsPathComponent::Name("given_name".to_owned()),
            ])
        } else {
            ClaimsPath(vec![
                ClaimsPathComponent::Name("names".to_owned()),
                ClaimsPathComponent::Index(index),
                ClaimsPathComponent::Name("given_name".to_owned()),
            ])
        };

        let processed = process_json_claims_path(&credential, &path);
        if use_all {
            prop_assert_eq!(processed.map(|values| values.values().len()).ok(), Some(2));
        } else {
            prop_assert_eq!(processed.is_ok(), index < 2);
        }
    }

    #[test]
    fn malformed_request_transport_vectors_do_not_accept(
        client_count in 0_usize..3,
        request_count in 0_usize..3,
        request_uri_count in 0_usize..3,
    ) {
        let mut parts = Vec::new();
        parts.extend(vec!["client_id=x509_san_dns%3Averifier.example"; client_count]);
        parts.extend(vec!["request=header.payload.signature"; request_count]);
        parts.extend(vec!["request_uri=https%3A%2F%2Fverifier.example%2Frequest.jwt"; request_uri_count]);
        let input = parts.join("&");
        let vector = ConformanceVector {
            id: "property-transport".to_owned(),
            spec_section: "OpenID4VP 1.0 Final Authorization Request".to_owned(),
            target: "wallet::AuthorizationRequestTransport".to_owned(),
            input,
            expected: ExpectedResult::Reject,
        };
        let exactly_one_request_source = request_count + request_uri_count == 1;
        let no_duplicate_client = client_count <= 1;
        if !exactly_one_request_source || !no_duplicate_client {
            prop_assert_eq!(run_vector(&vector)?, VectorOutcome::Passed);
        }
    }

    #[test]
    fn authorization_response_proto_shape_fails_closed(
        query_id in identifier_strategy(),
        presentation_count in 0_usize..3,
        include_state in any::<bool>(),
    ) {
        let proto = pb::AuthorizationResponse {
            vp_token: vec![pb::VpTokenEntry {
                query_id: query_id.clone(),
                presentations: vec![compact_presentation(); presentation_count],
                __buffa_unknown_fields: Default::default(),
            }],
            state: include_state.then(|| "fedcba9876543210".to_owned()),
            __buffa_unknown_fields: Default::default(),
        };
        let parsed = proto_to_authorization_response(&proto);
        let valid_query_id = QueryId::parse(&query_id).is_ok();
        prop_assert_eq!(parsed.is_ok(), valid_query_id && presentation_count > 0);
    }

    #[test]
    fn generated_authorization_request_json_decoder_is_total(
        bytes in vec(any::<u8>(), 0..128),
    ) {
        if let Ok(json) = core::str::from_utf8(&bytes) {
            let decoded = authorization_request_json_to_proto(json);
            if let Ok(proto) = decoded {
                let encoded = authorization_request_proto_to_json(&proto);
                prop_assert!(encoded.is_ok());
            }
        }
    }

    #[test]
    fn dcql_evaluation_candidate_matrix_fails_closed(
        query_requires_binding in any::<bool>(),
        candidate_has_binding in any::<bool>(),
        include_claim in any::<bool>(),
        candidate_has_claim in any::<bool>(),
        candidate_wrong_format in any::<bool>(),
    ) {
        let Ok(query) = dcql_evaluation_query(query_requires_binding, include_claim) else {
            prop_assert!(false, "test DCQL evaluation query must be constructible");
            return Ok(());
        };
        let Ok(candidate) = dcql_evaluation_candidate(
            candidate_has_binding,
            candidate_has_claim,
            candidate_wrong_format,
        ) else {
            prop_assert!(false, "test DCQL candidate must be constructible");
            return Ok(());
        };
        let expected = !candidate_wrong_format
            && (!query_requires_binding || candidate_has_binding)
            && (!include_claim || candidate_has_claim);

        prop_assert_eq!(evaluate_query(&query, &[candidate]).is_ok(), expected);
    }

    #[test]
    fn dc_api_request_kind_matrix_fails_closed(
        kind_case in 0_u8..3,
        response_mode_is_jwt in any::<bool>(),
        has_client_id in any::<bool>(),
        has_expected_origin in any::<bool>(),
    ) {
        let kind = dc_api_kind(kind_case);
        let request = dc_api_matrix_request(
            response_mode_is_jwt,
            has_client_id,
            has_expected_origin,
        );
        let expected = match kind {
            // Appendix A.2 requires both identity members to be ignored for
            // browser-origin-bound unsigned requests, not rejected.
            DcApiRequestKind::Unsigned => true,
            DcApiRequestKind::Signed | DcApiRequestKind::Multisigned => false,
        };

        prop_assert_eq!(
            DigitalCredentialGetRequest::new(DcApiProtocol::v1(kind), request).is_ok(),
            expected
        );
    }

    #[test]
    fn direct_post_form_handler_matrix_fails_closed(
        method_is_post in any::<bool>(),
        content_type_is_form in any::<bool>(),
        include_vp_token in any::<bool>(),
        state_case in 0_u8..4,
    ) {
        let status = direct_post_matrix_status(
            method_is_post,
            content_type_is_form,
            include_vp_token,
            state_case,
        );
        let expected_success = method_is_post
            && content_type_is_form
            && include_vp_token
            && state_case == 1;

        prop_assert_eq!(status < 300, expected_success);
    }

    #[test]
    fn verifier_attestation_binding_matrix_fails_closed(
        subject_matches in any::<bool>(),
        restricts_redirects in any::<bool>(),
        request_has_redirect in any::<bool>(),
        redirect_matches in any::<bool>(),
    ) {
        let expected = subject_matches
            && (!restricts_redirects || (request_has_redirect && redirect_matches));

        prop_assert_eq!(
            verifier_attestation_matrix_result(
                subject_matches,
                restricts_redirects,
                request_has_redirect,
                redirect_matches,
            ),
            expected
        );
    }
}

fn identifier_strategy() -> impl Strategy<Value = String> {
    vec(select(identifier_chars()), 0..140).prop_map(|chars| chars.into_iter().collect())
}

fn identifier_chars() -> Vec<char> {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.:/"
        .chars()
        .collect()
}

fn dcql_query_for_claim_set_case(case: u8) -> Result<DcqlQuery, DcqlError> {
    let claim_id = QueryId::parse("given_name")?;
    let claims = match case {
        1 => None,
        2 => Some(Vec::new()),
        _ => Some(vec![ClaimQuery {
            id: Some(claim_id.clone()),
            path: ClaimsPath(vec![ClaimsPathComponent::Name("given_name".to_owned())]),
            values: None,
            intent_to_retain: None,
        }]),
    };
    let claim_sets = match case {
        0 => Some(vec![ClaimSet(vec![claim_id])]),
        1 => Some(vec![ClaimSet(vec![QueryId::parse("pid")?])]),
        2 => None,
        3 => None,
        _ => Some(vec![ClaimSet(vec![QueryId::parse("pid")?])]),
    };
    Ok(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid")?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
            multiple: false,
            meta: sd_jwt_meta(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims,
            claim_sets,
        }],
        credential_sets: None,
    })
}

fn compact_presentation() -> pb::PresentationValue {
    pb::PresentationValue {
        kind: Some(pb::presentation_value::Kind::Compact(
            "presentation".to_owned(),
        )),
        __buffa_unknown_fields: Default::default(),
    }
}

fn dcql_evaluation_query(
    require_binding: bool,
    include_claim: bool,
) -> Result<DcqlQuery, DcqlError> {
    let claims = include_claim
        .then(|| {
            QueryId::parse("given_name").map(|id| {
                vec![ClaimQuery {
                    id: Some(id),
                    path: ClaimsPath(vec![ClaimsPathComponent::Name("given_name".to_owned())]),
                    values: None,
                    intent_to_retain: None,
                }]
            })
        })
        .transpose()?;
    Ok(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid")?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())?,
            multiple: false,
            meta: sd_jwt_meta(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: require_binding,
            claims,
            claim_sets: None,
        }],
        credential_sets: None,
    })
}

fn dcql_evaluation_candidate(
    has_binding: bool,
    has_claim: bool,
    wrong_format: bool,
) -> Result<CredentialCandidate, DcqlError> {
    let format_name = if wrong_format {
        CredentialFormat::MSO_MDOC
    } else {
        CredentialFormat::DC_SD_JWT
    };
    let claims = if has_claim {
        json!({"given_name": "Ada"})
    } else {
        json!({"family_name": "Lovelace"})
    };
    Ok(CredentialCandidate {
        id: EvaluationCredential::new("cred-1".to_owned())?,
        format: CredentialFormat::new(format_name.to_owned())?,
        meta: sd_jwt_meta(),
        claims,
        cryptographic_holder_binding: has_binding,
    })
}

fn sd_jwt_meta() -> JsonMap<String, serde_json::Value> {
    JsonMap::from_iter([(
        "vct_values".to_owned(),
        json!(["https://credentials.example.com/identity_credential"]),
    )])
}

fn dc_api_kind(case: u8) -> DcApiRequestKind {
    match case {
        0 => DcApiRequestKind::Unsigned,
        1 => DcApiRequestKind::Signed,
        _ => DcApiRequestKind::Multisigned,
    }
}

fn dc_api_matrix_request(
    response_mode_is_jwt: bool,
    has_client_id: bool,
    has_expected_origin: bool,
) -> AuthorizationRequestObject {
    let response_mode = if response_mode_is_jwt {
        ResponseMode::DcApiJwt
    } else {
        ResponseMode::DcApi
    };
    AuthorizationRequestObject {
        client_id: has_client_id
            .then(|| ClientIdentifier::parse("x509_san_dns:verifier.example"))
            .and_then(Result::ok),
        response_type: ResponseType::VpToken,
        response_mode: Some(response_mode),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: direct_post_dcql_query().expect("test DCQL query is valid"),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: has_expected_origin.then(|| vec!["https://rp.example".to_owned()]),
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    }
}

fn direct_post_matrix_status(
    method_is_post: bool,
    content_type_is_form: bool,
    include_vp_token: bool,
    state_case: u8,
) -> u16 {
    let service = Arc::new(VerifierRuntimeService::new(
        VerifierRuntimeConfig::new()
            .with_holder_binding_verifier(Arc::new(FixtureHolderBindingVerifier)),
    ));
    let Some(session) = direct_post_session() else {
        return 500;
    };
    let runtime = VerifierHttpRuntime::new(
        service,
        Arc::new(FixtureSessionStore {
            session: Mutex::new(Some(session)),
        }),
        Arc::new(FixtureRequestObjectStore),
        Arc::new(FixtureClock),
    );
    let mut parts = Vec::new();
    if include_vp_token {
        parts.push("vp_token=%7B%22pid%22%3A%5B%22presentation%22%5D%7D");
    }
    match state_case {
        0 => {}
        1 => parts.push("state=fedcba9876543210"),
        2 => parts.push("state=other"),
        _ => {
            parts.push("state=fedcba9876543210");
            parts.push("state=other");
        }
    }
    let request = RuntimeHttpRequest {
        method: if method_is_post {
            RuntimeHttpMethod::Post
        } else {
            RuntimeHttpMethod::Get
        },
        accept: None,
        content_type: content_type_is_form.then(|| "application/x-www-form-urlencoded".to_owned()),
        body: parts.join("&").into_bytes(),
    };
    let response = runtime.handle(
        VerifierHttpEndpoint::DirectPost {
            session_key: "session",
        },
        &request,
    );
    response.status
}

#[test]
fn direct_post_matrix_accepts_canonical_success_case() {
    let status = direct_post_matrix_status(true, true, true, 1);

    assert_eq!(status, 200);
}

struct FixtureHolderBindingVerifier;
struct FixtureSessionStore {
    session: Mutex<Option<SessionRecord>>,
}
struct FixtureRequestObjectStore;
struct FixtureClock;

impl HolderBindingVerifier for FixtureHolderBindingVerifier {
    fn verify_holder_binding(
        &self,
        _presentation: &PresentationValue,
        _context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec!["x509_san_dns:verifier.example".to_owned()],
                nonce: "0123456789abcdef".to_owned(),
                expiration_unix: 100,
                issued_at_unix: 10,
                sd_hash: None,
                transaction_data_hashes: Vec::new(),
                transaction_data_hashes_alg: None,
            },
            VerifiedDisclosureSet::Derived,
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}

impl VerifierSessionStore for FixtureSessionStore {
    fn load_session(&self, key: &str) -> Result<SessionRecord, RuntimeError> {
        if key != "session" {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        self.session
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionNotFound))?
            .clone()
            .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::SessionNotFound))
    }

    fn reserve_session(&self, key: &str) -> Result<SessionReservation, RuntimeError> {
        if key != "session" {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        let session = self
            .session
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionReservationConflict))?
            .take()
            .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::SessionAlreadyConsumed))?;
        Ok(SessionReservation::new(session, [7_u8; 32]))
    }

    fn release_session(
        &self,
        key: &str,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        if key != "session" {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        let mut session = self
            .session
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed))?;
        if session.is_some() {
            return Err(RuntimeError::new(
                RuntimeErrorReason::SessionReservationConflict,
            ));
        }
        *session = Some(reservation.session().clone());
        Ok(())
    }

    fn commit_verified_authorization_response(
        &self,
        key: &str,
        reservation: &SessionReservation,
        response_code: &ResponseCode,
        result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError> {
        if key != "session" || reservation.reservation_id() != &[7_u8; 32] {
            return Err(RuntimeError::new(
                RuntimeErrorReason::SessionReservationConflict,
            ));
        }
        if result.result().presentations().is_empty() {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed));
        }
        if response_code.as_str().len() < reallyme_openid4vp_runtime::MIN_RESPONSE_CODE_CHARS {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseCode));
        }
        Ok(())
    }

    fn redeem_follow_back(
        &self,
        _response_code: &ResponseCode,
        _browser_session: &BrowserSessionBinding,
        _now_unix: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(
            RuntimeErrorReason::InvalidFollowBackRequirement,
        ))
    }
}

impl RequestObjectStore for FixtureRequestObjectStore {
    fn load_request_object(&self, _key: &str) -> Result<HostedRequestObject, RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

impl RuntimeClock for FixtureClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(10)
    }
}

fn direct_post_session() -> Option<SessionRecord> {
    let client_id = ClientIdentifier::parse("x509_san_dns:verifier.example").ok()?;
    Some(SessionRecord {
        binding: RequestBinding {
            client_id,
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: direct_post_dcql_query()?,
        response_mode: reallyme_openid4vp_types::ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    })
}

fn direct_post_dcql_query() -> Option<DcqlQuery> {
    Some(DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").ok()?,
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()).ok()?,
            multiple: false,
            meta: sd_jwt_meta(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    })
}

fn verifier_attestation_matrix_result(
    subject_matches: bool,
    restricts_redirects: bool,
    request_has_redirect: bool,
    redirect_matches: bool,
) -> bool {
    let Ok(attestation) = VerifiedVerifierAttestation::new(
        if subject_matches {
            "verifier.example".to_owned()
        } else {
            "other.example".to_owned()
        },
        restricts_redirects.then(|| vec!["https://verifier.example/cb".to_owned()]),
        vec![1_u8],
        100,
    ) else {
        return false;
    };
    let mut request = dc_api_matrix_request(true, true, true);
    request.client_id = ClientIdentifier::parse("verifier_attestation:verifier.example").ok();
    request.redirect_uri = if request_has_redirect {
        Some(if redirect_matches {
            "https://verifier.example/cb".to_owned()
        } else {
            "https://verifier.example/other".to_owned()
        })
    } else {
        None
    };
    validate_verifier_attestation_binding(&request, &attestation, &[1_u8], 99).is_ok()
}
