// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(clippy::expect_used, reason = "bounded test fixture setup")]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::encode_zk_prepared_persona_value;
use reallyme_openid4vp_types::{ClientIdentifier, ResponseMode};
use reallyme_zk_api::ZkIssuerPublicKey;
use serde_json::json;

use super::{ZkHolderBindingVerifier, ZkVerificationRequirements};
use crate::{
    HolderBindingVerificationContext, HolderBindingVerifier, RequestBinding, SessionRecord,
    VerifierErrorReason,
};

struct NeverBundle;

impl reallyme_zk_api::ZkBundleVerifier for NeverBundle {
    fn verify_bundle_evidence(
        &self,
        _request: reallyme_zk_api::ZkBundleVerifyRequest<'_>,
    ) -> Result<(), reallyme_zk_api::ZkError> {
        Err(reallyme_zk_api::ZkError::new(
            reallyme_zk_api::ZkErrorReason::InvalidProof,
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
fn prepared_profiles_fail_closed_without_complete_verifier() {
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
