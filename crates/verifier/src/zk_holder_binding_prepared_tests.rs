// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(clippy::expect_used, reason = "bounded test fixture setup")]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::encode_zk_prepared_persona_value;
use reallyme_openid4vp_types::{ClientIdentifier, ResponseMode};
use reallyme_zk_api::keys::ZkIssuerPublicKey;
use serde_json::json;

use super::{ZkHolderBindingVerifier, ZkVerificationRequirements};
use crate::{
    HolderBindingVerificationContext, HolderBindingVerifier, RequestBinding, SessionRecord,
    VerifierErrorReason,
};

struct NeverBundle;

impl reallyme_zk_api::claim_bundle::ZkPresentationBoundClaimBundleVerifier for NeverBundle {
    fn verify_presentation_bound_claim_bundle_evidence(
        &self,
        _request: reallyme_zk_api::claim_bundle::ZkPresentationBoundClaimBundleVerifyRequest<'_>,
    ) -> Result<(), reallyme_zk_api::errors::ZkError> {
        Err(reallyme_zk_api::errors::ZkError::new(
            reallyme_zk_api::errors::ZkErrorReason::InvalidProof,
        ))
    }
}

fn session(profile: &str) -> SessionRecord {
    let meta = json!({
        "profile": profile,
        "hash_strategy": "sha256",
        "claim_name_hash": "0303030303030303030303030303030303030303030303030303030303030303",
        "claim_value_b64u": "CQ"
    })
    .as_object()
    .expect("fixture object")
    .clone();
    SessionRecord {
        binding: RequestBinding {
            client_id: ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("fixture client"),
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
                id: QueryId::parse("pid").expect("fixture id"),
                format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
                    .expect("fixture format"),
                multiple: false,
                meta,
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

#[test]
fn evidence_modes_fail_closed_without_complete_verifier() {
    let backend = NeverBundle;
    let issuer = [ZkIssuerPublicKey {
        x: [0_u8; 32],
        y: [0_u8; 32],
    }];
    let verifier = ZkHolderBindingVerifier::new(
        &backend,
        &issuer,
        ZkVerificationRequirements {
            issuer_signed_validity: true,
            credential_status: true,
        },
    );
    let presentation =
        encode_zk_prepared_persona_value(&[1_u8; 16]).expect("transport fixture is bounded");
    for profile in [
        "persona_credential_evidence_public_persona_v1",
        "persona_credential_evidence_private_persona_one_time_v1",
    ] {
        let session = session(profile);
        let result = verifier.verify_holder_binding(
            &presentation,
            HolderBindingVerificationContext::new(&session, &session.dcql_query.credentials[0], 11),
        );
        assert_eq!(
            result
                .expect_err("missing complete verifier must fail")
                .reason(),
            VerifierErrorReason::UnsupportedFormat
        );
    }
}

struct CapturingEvidenceVerifier {
    mode: reallyme_zk_api::persona_evidence::ZkPersonaCredentialEvidenceMode,
    algorithm: reallyme_zk_api::circuits::ZkCredentialHashAlgorithm,
    calls: std::sync::atomic::AtomicUsize,
}

impl super::ZkPersonaCredentialEvidenceProofVerifier for CapturingEvidenceVerifier {
    fn verify_persona_credential_evidence(
        &self,
        request: super::ZkPersonaCredentialEvidenceVerifyRequest<'_>,
    ) -> Result<
        reallyme_zk_api::persona_evidence::ZkVerifiedPersonaCredentialEvidence,
        crate::VerifierError,
    > {
        use sha2::{Digest, Sha256};

        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(request.presentation_bytes, [1_u8; 16]);
        assert_eq!(request.mode, self.mode);
        assert_eq!(request.hash_strategy, self.algorithm);
        assert_eq!(*request.claim_name_hash, [3; 32]);
        assert_eq!(request.claim_value, [9]);
        assert_eq!(request.response_mode, ResponseMode::DirectPost);
        assert_eq!(request.issued_at_unix, 10);
        assert_eq!(request.expires_at_unix, 100);
        assert_eq!(request.now_unix, 11);
        let expected_nonce: [u8; 32] = Sha256::digest(b"0123456789abcdef").into();
        let expected_audience: [u8; 32] = Sha256::digest(b"x509_san_dns:verifier.example").into();
        assert_eq!(request.request_hashes.nonce, expected_nonce);
        assert_eq!(request.request_hashes.audience_sha256, expected_audience);
        Err(crate::VerifierError::new(
            VerifierErrorReason::InvalidZkPresentation,
        ))
    }
}

#[test]
fn evidence_dispatch_preserves_mode_lane_and_verifier_owned_request() {
    use reallyme_zk_api::{
        circuits::ZkCredentialHashAlgorithm, persona_evidence::ZkPersonaCredentialEvidenceMode,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    let presentation = encode_zk_prepared_persona_value(&[1_u8; 16]).expect("bounded fixture");
    for mode in [
        ZkPersonaCredentialEvidenceMode::PublicPersonaV1,
        ZkPersonaCredentialEvidenceMode::PrivatePersonaOneTimeV1,
    ] {
        for algorithm in [
            ZkCredentialHashAlgorithm::Sha256,
            ZkCredentialHashAlgorithm::Poseidon2,
        ] {
            let backend = CapturingEvidenceVerifier {
                mode,
                algorithm,
                calls: AtomicUsize::new(0),
            };
            let verifier = ZkHolderBindingVerifier::new(
                &NeverBundle,
                &[],
                ZkVerificationRequirements {
                    issuer_signed_validity: true,
                    credential_status: true,
                },
            )
            .with_persona_credential_evidence(&backend);
            let mut session = session(mode.as_str());
            session.dcql_query.credentials[0]
                .meta
                .insert("hash_strategy".to_owned(), json!(algorithm.as_str()));
            let result = verifier.verify_holder_binding(
                &presentation,
                HolderBindingVerificationContext::new(
                    &session,
                    &session.dcql_query.credentials[0],
                    11,
                ),
            );
            assert_eq!(
                result
                    .expect_err("backend rejection must propagate")
                    .reason(),
                VerifierErrorReason::InvalidZkPresentation
            );
            assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        }
    }
}
