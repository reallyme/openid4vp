// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use serde_json::{json, Map as JsonMap, Value as JsonValue};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use reallyme_credential_status::{
    status_list_signing_payload, CredentialStatusError, StatusList, StatusListAlgorithm,
    StatusListFreshnessPolicy, StatusListSignature, StatusListVerifier, StatusPurpose,
};
use sha2::{Digest, Sha256};

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, encode_zk_presentation_value, ZkPresentation,
    ZkPresentationCircuitRef, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_types::{
    AuthorizationResponse, ClientIdentifier, PresentationValue, ResponseMode,
    TransactionDataHashAlgorithm,
};
use reallyme_zk_api::{
    circuits::ZkCircuitRef,
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        ZkClaimProofBundleKind, ZkClaimProofBundleStage, ZkPresentationBoundClaimBundleVerifier,
        ZkPresentationBoundClaimBundleVerifyRequest,
    },
    common_root::ZkCommonCredentialRootPersonaMode,
    common_root::{
        ZkCommonCredentialRootIssuerStatusExpectation, ZkCommonCredentialRootProofSlot,
        ZkCommonCredentialRootRawPublicInputs, ZkCommonCredentialRootVerifier,
        ZkCommonCredentialRootVerifyRequest, ZkRootStatusSnapshot, ZkRootStatusTrustPolicy,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::{ZkIssuerCredentialStatusProof, ZkIssuerCredentialStatusVerifier},
    issuer_status::{
        ZkIssuerStatusAuthority, ZkIssuerStatusFeed, ZkIssuerStatusListPointer,
        ZkIssuerStatusPurpose,
    },
    keys::ZkIssuerPublicKey,
    proofs::{ZkPublicInputDescriptor, ZkPublicInputName, ZkSessionBinding},
};

use super::query::{parse_lower_hex_hash, parse_query_policy};
use super::status::ZkVerifiedIssuerStatus;
use super::{
    VerifierError, VerifierErrorReason, ZkCommonCredentialRootTrustPolicy,
    ZkCommonCredentialRootVerificationPolicy, ZkHolderBindingVerifier, ZkIssuerStatusRollbackFloor,
    ZkIssuerStatusTrust, ZkRootStatusRollbackFloor, ZkVerificationRequirements,
};
use crate::{
    diagnose_authorization_response_with_options, HolderBindingVerificationContext,
    HolderBindingVerifier, RequestBinding, ResponseValidationOptions, SessionRecord,
    TransactionDataBinding, VerifiedDisclosureSet, VerifiedTrustProvenance,
};

fn valid_meta() -> JsonMap<String, JsonValue> {
    json!({
        "profile": "credential_subject_claim_v1",
        "hash_strategy": "sha256",
        "claim_name_hash": "0303030303030303030303030303030303030303030303030303030303030303",
        "claim_value_b64u": "CQ"
    })
    .as_object()
    .expect("fixture is a JSON object")
    .clone()
}

#[test]
fn accepts_exact_bounded_query_policy() {
    let policy = parse_query_policy(&valid_meta()).expect("valid query policy is accepted");
    assert_eq!(policy.claim_name_hash, [3_u8; 32]);
    assert_eq!(
        policy.claim_value.as_ref().map(|value| value.as_slice()),
        Some(&[9][..])
    );
}

#[test]
fn rejects_malformed_claim_policy_without_echoing_values() {
    let mut meta = valid_meta();
    for (name, value) in [
        ("claim_name_hash", JsonValue::String("03".to_owned())),
        ("claim_value_b64u", JsonValue::String("CQ==".to_owned())),
        ("profile", JsonValue::String("unknown".to_owned())),
        ("hash_strategy", JsonValue::String("unknown".to_owned())),
    ] {
        let original = meta.insert(name.to_owned(), value);
        let error = parse_query_policy(&meta)
            .map(|_| ())
            .expect_err("invalid policy must fail closed");
        assert_eq!(error.reason(), VerifierErrorReason::VpTokenQueryMismatch);
        let previous = original.expect("fixture contains this member");
        meta.insert(name.to_owned(), previous);
    }
    meta.insert("unreviewed".to_owned(), JsonValue::Bool(true));
    assert_eq!(
        parse_query_policy(&meta)
            .map(|_| ())
            .expect_err("unknown policy field must fail closed")
            .reason(),
        VerifierErrorReason::VpTokenQueryMismatch
    );
    assert_eq!(
        parse_lower_hex_hash("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
            .expect_err("uppercase hex is not canonical")
            .reason(),
        VerifierErrorReason::VpTokenQueryMismatch
    );
}

struct EvidenceVerifier {
    calls: AtomicUsize,
    accept: bool,
}

impl ZkPresentationBoundClaimBundleVerifier for EvidenceVerifier {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        _request: ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.accept {
            Ok(())
        } else {
            Err(ZkError::new(ZkErrorReason::InvalidProof))
        }
    }
}

struct StatusEvidenceVerifier;

impl ZkIssuerCredentialStatusVerifier for StatusEvidenceVerifier {
    fn verify_issuer_credential_status(
        &self,
        _proof: &ZkIssuerCredentialStatusProof,
    ) -> Result<(), ZkError> {
        Ok(())
    }
}

struct StatusAuthority;

impl ZkIssuerStatusAuthority for StatusAuthority {
    fn current_feed_for_issuer(
        &self,
        issuer: &ZkIssuerPublicKey,
        pointer: &ZkIssuerStatusListPointer,
        _verification_time_unix: u64,
    ) -> Result<ZkIssuerStatusFeed, ZkError> {
        if *issuer != TRUSTED_ISSUER
            || pointer.list_id != [0x42; 32]
            || pointer.url_hash != [0x43; 32]
            || pointer.purpose != ZkIssuerStatusPurpose::Revocation
        {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
        Ok(ZkIssuerStatusFeed {
            root: [0x41; 32],
            length: 256,
            list_id: [0x42; 32],
            url_hash: [0x43; 32],
            purpose: ZkIssuerStatusPurpose::Revocation,
        })
    }
}

static STATUS_EVIDENCE_VERIFIER: StatusEvidenceVerifier = StatusEvidenceVerifier;
static STATUS_AUTHORITY: StatusAuthority = StatusAuthority;

fn status_qualified_verifier<'a>(
    backend: &'a EvidenceVerifier,
    issuers: &'a [ZkIssuerPublicKey],
) -> ZkHolderBindingVerifier<'a> {
    ZkHolderBindingVerifier::new(backend, issuers, STATUS_REQUIREMENTS)
        .with_issuer_credential_status(
            &STATUS_EVIDENCE_VERIFIER,
            &STATUS_AUTHORITY,
            ZkIssuerStatusPurpose::Revocation,
        )
}

fn session() -> SessionRecord {
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client identifier is valid"),
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            request_time_unix: 10,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query identifier is valid"),
                format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta: valid_meta(),
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        response_mode: ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    }
}

#[allow(clippy::panic)]
fn stage_kind(stage: ZkClaimProofBundleStage) -> ZkPresentationStageKind {
    match stage {
        ZkClaimProofBundleStage::Session => ZkPresentationStageKind::Session,
        ZkClaimProofBundleStage::CredentialEnvelope => ZkPresentationStageKind::CredentialEnvelope,
        ZkClaimProofBundleStage::CredentialRoot => ZkPresentationStageKind::CredentialRoot,
        ZkClaimProofBundleStage::Claim => ZkPresentationStageKind::Claim,
        _ => panic!("test fixture covers the production stages"),
    }
}

fn write_field(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) {
    let range = descriptor.field_range(name).expect("fixture field exists");
    bytes[range].copy_from_slice(value);
}

#[allow(clippy::panic)]
fn public_inputs(circuit_ref: ZkCircuitRef, binding: ZkSessionBinding) -> Vec<u8> {
    let descriptor =
        ZkPublicInputDescriptor::for_circuit(circuit_ref).expect("fixture circuit has an ABI");
    let mut bytes = vec![0_u8; descriptor.encoded_len().expect("fixture ABI is bounded")];
    for field in descriptor.fields() {
        match field.name {
            ZkPublicInputName::Challenge => {
                write_field(&mut bytes, descriptor, field.name, &binding.nonce_hash);
            }
            ZkPublicInputName::AudienceHash => {
                write_field(&mut bytes, descriptor, field.name, &binding.audience_hash);
            }
            ZkPublicInputName::TransactionDataHash => {
                write_field(
                    &mut bytes,
                    descriptor,
                    field.name,
                    &binding.transaction_data_public_input(),
                );
            }
            ZkPublicInputName::ExpiryUnix => {
                write_field(&mut bytes, descriptor, field.name, &20_u64.to_be_bytes());
            }
            ZkPublicInputName::SessionBinding => {
                write_field(&mut bytes, descriptor, field.name, &[12_u8; 32]);
            }
            ZkPublicInputName::EnvelopeBinding => {
                write_field(&mut bytes, descriptor, field.name, &[13_u8; 32]);
            }
            ZkPublicInputName::CredentialBinding => {
                write_field(&mut bytes, descriptor, field.name, &[14_u8; 32]);
            }
            ZkPublicInputName::ClaimNameHash => {
                write_field(&mut bytes, descriptor, field.name, &[3_u8; 32]);
            }
            ZkPublicInputName::ValueLength => {
                write_field(&mut bytes, descriptor, field.name, &1_u32.to_be_bytes());
            }
            ZkPublicInputName::Value => {
                let mut value = [0_u8; 64];
                value[0] = 9;
                write_field(&mut bytes, descriptor, field.name, &value);
            }
            ZkPublicInputName::IssuerPublicKeyX | ZkPublicInputName::IssuerPublicKeyY => {}
            _ => panic!("fixture does not support this public input"),
        }
    }
    bytes
}

fn write_raw_bytes32(bytes: &mut [u8], first_field: usize, value: [u8; 32]) {
    for (index, byte) in value.into_iter().enumerate() {
        bytes[(first_field + index) * 32 + 31] = byte;
    }
}

fn write_raw_u64(bytes: &mut [u8], field: usize, value: u64) {
    let start = field * 32 + 24;
    bytes[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn issuer_status_stage(binding: ZkSessionBinding) -> ZkPresentationStage {
    let circuit_ref = ZkCircuitRef::new(
        ZkCredentialHashAlgorithm::Sha256,
        reallyme_zk_api::circuits::ZkCircuitFamily::CommonCredentialRootV1,
        reallyme_zk_api::circuits::ZkCircuitStage::IssuerCredentialStatus,
    );
    let mut public_inputs = vec![0_u8; 292 * 32];
    write_raw_bytes32(&mut public_inputs, 0, binding.nonce_hash);
    write_raw_bytes32(&mut public_inputs, 32, binding.audience_hash);
    write_raw_bytes32(
        &mut public_inputs,
        64,
        binding.transaction_data_public_input(),
    );
    write_raw_bytes32(&mut public_inputs, 96, TRUSTED_ISSUER.x);
    write_raw_bytes32(&mut public_inputs, 128, TRUSTED_ISSUER.y);
    write_raw_u64(&mut public_inputs, 160, 20);
    write_raw_bytes32(&mut public_inputs, 161, [14; 32]);
    write_raw_bytes32(&mut public_inputs, 193, [0x41; 32]);
    write_raw_u64(&mut public_inputs, 225, 256);
    write_raw_bytes32(&mut public_inputs, 226, [0x42; 32]);
    write_raw_bytes32(&mut public_inputs, 258, [0x43; 32]);
    public_inputs[290 * 32 + 31] = 1;
    write_raw_u64(&mut public_inputs, 291, 10);
    ZkCommonCredentialRootRawPublicInputs::try_copy_from_slice(circuit_ref, &public_inputs)
        .expect("fixture follows the raw circuit ABI");
    ZkPresentationStage {
        stage: ZkPresentationStageKind::IssuerCredentialStatus,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: circuit_ref.credential_hash_algorithm.as_str().to_owned(),
            family: circuit_ref.family.as_str().to_owned(),
            stage: circuit_ref.stage.as_str().to_owned(),
            version: circuit_ref.revision,
        },
        artifact_identity: reallyme_openid4vp_formats::ZkPresentationArtifactIdentity::ArtifactSet(
            [7; 32],
        ),
        proof: vec![5],
        public_inputs,
    }
}

fn presentation() -> PresentationValue {
    presentation_for("x509_san_dns:verifier.example", None)
}

fn presentation_for(audience: &str, transaction_data_hash: Option<[u8; 32]>) -> PresentationValue {
    let binding =
        build_zk_presentation_binding("0123456789abcdef", audience, transaction_data_hash);
    let session_binding = ZkSessionBinding {
        nonce_hash: binding.nonce_hash,
        audience_hash: binding.audience_hash,
        transaction_data_hash,
    };
    let mut stages: Vec<_> =
        ZkClaimProofBundleStage::ALL
            .iter()
            .map(|stage| {
                let circuit_ref = ZkClaimProofBundleKind::CredentialSubjectClaimV1
                    .source_ref(ZkCredentialHashAlgorithm::Sha256, *stage);
                ZkPresentationStage {
                    stage: stage_kind(*stage),
                    circuit_ref: ZkPresentationCircuitRef {
                        hash_strategy: circuit_ref.credential_hash_algorithm.as_str().to_owned(),
                        family: circuit_ref.family.as_str().to_owned(),
                        stage: circuit_ref.stage.as_str().to_owned(),
                        version: circuit_ref.revision,
                    },
                    artifact_identity:
                        reallyme_openid4vp_formats::ZkPresentationArtifactIdentity::Manifest(
                            [7_u8; 32],
                        ),
                    proof: vec![stage.index() + 1],
                    public_inputs: public_inputs(circuit_ref, session_binding),
                }
            })
            .collect();
    stages.push(issuer_status_stage(session_binding));
    encode_zk_presentation_value(ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::CredentialSubjectClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding,
    })
    .expect("test envelope has valid shape")
}

const TRUSTED_ISSUER: ZkIssuerPublicKey = ZkIssuerPublicKey {
    x: [0_u8; 32],
    y: [0_u8; 32],
};

const STATUS_REQUIREMENTS: ZkVerificationRequirements = ZkVerificationRequirements {
    issuer_signed_validity: true,
    credential_status: true,
};

#[test]
fn verified_bundle_satisfies_exact_query() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let session = session();
    let result = verifier
        .verify_holder_binding(
            &presentation(),
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect("complete bundle and exact query are accepted");

    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        result.trust_provenance(),
        VerifiedTrustProvenance::VerifiedDerivedProof
    );
    assert!(matches!(
        result.disclosures(),
        VerifiedDisclosureSet::ZkClaim(claim)
            if claim.claim_name_hash() == &[3_u8; 32] && claim.claim_value() == [9]
    ));
    assert_eq!(result.claims().expiration_unix, 20);
}

#[test]
fn verified_bundle_discloses_selected_value_without_predetermined_match() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let mut session = session();
    session.dcql_query.credentials[0]
        .meta
        .remove("claim_value_b64u");

    let result = verifier
        .verify_holder_binding(
            &presentation(),
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect("the verified claim is disclosed when the query asks for its name");
    assert!(matches!(result.disclosures(),
        VerifiedDisclosureSet::ZkClaim(claim)
            if claim.claim_value() == [9] && claim.issuer() == TRUSTED_ISSUER
    ));
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_missing_or_substituted_issuer_status_evidence() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let session = session();
    let context =
        || HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10);
    let mut parsed = reallyme_openid4vp_formats::parse_zk_presentation_value(&presentation())
        .expect("fixture parses")
        .expect("fixture is ZK");
    parsed.stages.pop();
    let missing = encode_zk_presentation_value(parsed).expect("four-stage fixture encodes");
    assert!(verifier.verify_holder_binding(&missing, context()).is_err());

    let mut parsed = reallyme_openid4vp_formats::parse_zk_presentation_value(&presentation())
        .expect("fixture parses")
        .expect("fixture is ZK");
    let status = &mut parsed.stages[4].public_inputs;
    status[161 * 32 + 31] ^= 1;
    let substituted = encode_zk_presentation_value(parsed).expect("altered field encodes");
    assert_eq!(
        verifier
            .verify_holder_binding(&substituted, context())
            .expect_err("status proof from another credential fails")
            .reason(),
        VerifierErrorReason::InvalidZkPresentation,
    );

    let mut parsed = reallyme_openid4vp_formats::parse_zk_presentation_value(&presentation())
        .expect("fixture parses")
        .expect("fixture is ZK");
    let status = &mut parsed.stages[4].public_inputs;
    status[193 * 32 + 31] ^= 1;
    let stale_root = encode_zk_presentation_value(parsed).expect("altered field encodes");
    assert_eq!(
        verifier
            .verify_holder_binding(&stale_root, context())
            .expect_err("unadmitted status root fails")
            .reason(),
        VerifierErrorReason::InvalidZkPresentation,
    );
}

#[test]
fn complete_openid4vp_response_uses_verified_zk_provenance() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let session = session();
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query identifier is valid"),
        vec![presentation()],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let result = diagnose_authorization_response_with_options(
        &session,
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect("the complete response is bound to its active session and ZK query");

    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.verified_presentations().len(), 1);
    assert_eq!(
        result.verified_presentations()[0]
            .holder_binding()
            .trust_provenance(),
        VerifiedTrustProvenance::VerifiedDerivedProof
    );
}

#[test]
fn dc_api_transaction_presentation_binds_origin_and_digest() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let mut session = session();
    session.binding.response_uri = None;
    session.binding.dc_api_origin = Some("https://verifier.example".to_owned());
    session.binding.transaction_data_bindings = vec![TransactionDataBinding {
        query_id: QueryId::parse("pid").expect("test query identifier is valid"),
        algorithm: TransactionDataHashAlgorithm::Sha256,
        digest: [5_u8; 32],
    }];
    session.response_mode = ResponseMode::DcApi;
    let response = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query identifier is valid"),
        vec![presentation_for(
            "origin:https://verifier.example",
            Some([5_u8; 32]),
        )],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");

    let result = diagnose_authorization_response_with_options(
        &session,
        &response,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect("DC API response binds origin and exact transaction digest");
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(result.verified_presentations().len(), 1);

    let wrong_digest = AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query identifier is valid"),
        vec![presentation_for(
            "origin:https://verifier.example",
            Some([6_u8; 32]),
        )],
        Some("fedcba9876543210".to_owned()),
    )
    .expect("test response is valid");
    let error = diagnose_authorization_response_with_options(
        &session,
        &wrong_digest,
        10,
        ResponseValidationOptions {
            holder_binding_verifier: Some(&verifier),
        },
    )
    .expect_err("transaction-data substitution must fail before proof verification");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn tampered_public_input_fails_before_backend() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let session = session();
    let mut value = presentation();
    if let PresentationValue::Json(ref mut json) = value {
        json["stages"][0]["public_inputs"][0] = JsonValue::from(0);
    }
    let error = verifier
        .verify_holder_binding(
            &value,
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect_err("a public-input challenge mismatch must fail before backend use");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn backend_failure_and_wrong_claim_value_fail_closed() {
    let reject = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: false,
    };
    let active_session = session();
    let error = status_qualified_verifier(&reject, &[TRUSTED_ISSUER])
        .verify_holder_binding(
            &presentation(),
            HolderBindingVerificationContext::new(
                &active_session,
                &active_session.dcql_query.credentials[0],
                10,
            ),
        )
        .expect_err("backend rejection must fail closed");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(reject.calls.load(Ordering::SeqCst), 1);

    let accept = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let mut session = session();
    session.dcql_query.credentials[0].meta.insert(
        "claim_value_b64u".to_owned(),
        JsonValue::String("Cg".to_owned()),
    );
    let error = status_qualified_verifier(&accept, &[TRUSTED_ISSUER])
        .verify_holder_binding(
            &presentation(),
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect_err("a different requested claim value cannot be projected");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
}

#[test]
fn untrusted_issuer_and_unverified_labels_fail_before_backend() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let session = session();
    let untrusted = [ZkIssuerPublicKey {
        x: [1; 32],
        y: [2; 32],
    }];
    let error = status_qualified_verifier(&backend, &untrusted)
        .verify_holder_binding(
            &presentation(),
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect_err("issuer key must be admitted by verifier policy");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);

    let mut labelled = presentation();
    if let PresentationValue::Json(ref mut value) = labelled {
        value["derived_claims"] = json!([{
            "statement_id": "unverified",
            "statement": "age_over_18"
        }]);
    }
    let error = status_qualified_verifier(&backend, &[TRUSTED_ISSUER])
        .verify_holder_binding(
            &labelled,
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect_err("free-form derived labels cannot become verified claims");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_credential_assurance_requirements_fail_closed() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let session = session();
    for requirements in [
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: false,
        },
        ZkVerificationRequirements {
            issuer_signed_validity: false,
            credential_status: true,
        },
    ] {
        let error = ZkHolderBindingVerifier::new(&backend, &[TRUSTED_ISSUER], requirements)
            .verify_holder_binding(
                &presentation(),
                HolderBindingVerificationContext::new(
                    &session,
                    &session.dcql_query.credentials[0],
                    10,
                ),
            )
            .expect_err("v1 cannot prove issuer-signed validity or status");
        assert_eq!(error.reason(), VerifierErrorReason::UnsupportedFormat);
    }
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}

include!("zk_holder_binding_common_credential_root_support_tests.rs");
include!("zk_holder_binding_common_credential_root_status_tests.rs");
include!("zk_holder_binding_common_credential_root_verification_tests.rs");

#[test]
fn status_proof_time_allows_delay_but_rejects_future_or_predating_request() {
    assert!(super::validate_status_proof_time(1000, 1000, 1020).is_ok());
    assert!(super::validate_status_proof_time(1010, 1000, 1020).is_ok());
    for (proof_time, request_time, now) in [
        (999, 1000, 1020),
        (1021, 1000, 1020),
        (1000, 1001, 1000),
        (1000, 0, 1020),
    ] {
        assert_eq!(
            super::validate_status_proof_time(proof_time, request_time, now)
                .err()
                .map(|error| error.reason()),
            Some(VerifierErrorReason::InvalidZkPresentation),
        );
    }
}

#[test]
fn issuer_status_rejects_manifest_identity_even_when_digest_bytes_match() {
    let backend = EvidenceVerifier {
        calls: AtomicUsize::new(0),
        accept: true,
    };
    let verifier = status_qualified_verifier(&backend, &[TRUSTED_ISSUER]);
    let session = session();
    let mut parsed = reallyme_openid4vp_formats::parse_zk_presentation_value(&presentation())
        .expect("fixture parses")
        .expect("fixture is ZK");
    parsed.stages[4].artifact_identity =
        reallyme_openid4vp_formats::ZkPresentationArtifactIdentity::Manifest([7; 32]);
    let malformed =
        encode_zk_presentation_value(parsed).expect("shape is valid but construction is wrong");
    let error = verifier
        .verify_holder_binding(
            &malformed,
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 10),
        )
        .expect_err("issuer status requires a derived artifact-set identity");
    assert_eq!(error.reason(), VerifierErrorReason::InvalidZkPresentation);
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
}
