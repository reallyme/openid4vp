// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(clippy::expect_used, reason = "bounded test request fixtures")]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::parse_zk_prepared_persona_value;
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType,
};
use reallyme_zk_api::ZkPersonaCredentialEvidenceProfile;
use serde_json::json;
use zeroize::Zeroizing;

use super::{
    encode_zk_prepared_persona_response, prepare_zk_prepared_persona_request,
    prepare_zk_prepared_persona_response, prepare_zk_prepared_persona_unsigned_dc_api_request,
    prepare_zk_prepared_persona_unsigned_dc_api_response, WalletPreparedPersonaRequest,
    ZkPersonaCredentialEvidencePresentationProvider,
};
use crate::{
    validate_unsigned_dc_api_request, VerifiedPlatformOrigin, VerifiedWalletRequest,
    WalletAuthorizationRequest, WalletError, WalletErrorReason, WalletInvocationContext,
};

struct PreparedProvider {
    calls: usize,
}

impl ZkPersonaCredentialEvidencePresentationProvider for PreparedProvider {
    fn present(
        &mut self,
        request: &WalletPreparedPersonaRequest,
        _now_unix: u64,
    ) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        self.calls += 1;
        assert_eq!(
            request.profile(),
            ZkPersonaCredentialEvidenceProfile::PublicPersonaV1
        );
        Ok(Zeroizing::new(vec![7_u8; 32]))
    }
}

fn request(profile: &str, nonce: &str, expires_at_unix: Option<u64>) -> VerifiedWalletRequest {
    let meta = json!({
        "profile": profile,
        "hash_strategy": "sha256",
        "claim_name_hash": "0303030303030303030303030303030303030303030303030303030303030303",
        "claim_value_b64u": "dHJ1ZQ"
    })
    .as_object()
    .expect("fixture object")
    .clone();
    VerifiedWalletRequest::for_test(AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("fixture client identifier"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPostJwt),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: nonce.to_owned(),
        wallet_nonce: None,
        state: Some("opaque-state".to_owned()),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("age").expect("fixture query id"),
                format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
                    .expect("fixture credential format"),
                multiple: false,
                meta,
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: Some(10),
        exp: expires_at_unix,
    })
}

#[test]
fn prepared_wallet_request_binds_both_profiles_to_the_verified_request() {
    let id = QueryId::parse("age").expect("fixture id");
    let public = prepare_zk_prepared_persona_request(
        &request(
            "persona_credential_evidence_public_persona_v1",
            "first-nonce",
            Some(20),
        ),
        &WalletInvocationContext::ProtocolTransport,
        &id,
    )
    .expect("public request is valid");
    let private = prepare_zk_prepared_persona_request(
        &request(
            "persona_credential_evidence_private_persona_one_time_v1",
            "first-nonce",
            Some(20),
        ),
        &WalletInvocationContext::ProtocolTransport,
        &id,
    )
    .expect("private request is valid");
    let changed_nonce = prepare_zk_prepared_persona_request(
        &request(
            "persona_credential_evidence_public_persona_v1",
            "second-nonce",
            Some(20),
        ),
        &WalletInvocationContext::ProtocolTransport,
        &id,
    )
    .expect("second request is valid");
    assert_eq!(
        public.profile(),
        ZkPersonaCredentialEvidenceProfile::PublicPersonaV1
    );
    assert_eq!(
        private.profile(),
        ZkPersonaCredentialEvidenceProfile::PrivatePersonaOneTimeV1
    );
    assert_ne!(
        public.hashes().requested_claims_sha256,
        private.hashes().requested_claims_sha256
    );
    assert_ne!(public.hashes().nonce, changed_nonce.hashes().nonce);
    assert_eq!(public.claim_name_hash(), &[3_u8; 32]);
    assert_eq!(public.claim_value(), b"true");
    assert_eq!(public.issued_at_unix(), 10);
    assert_eq!(public.expires_at_unix(), 20);
}

#[test]
fn prepared_wallet_request_rejects_unsupported_policy_and_missing_time() {
    let id = QueryId::parse("age").expect("fixture id");
    let wrong_profile = request("legacy_private", "first-nonce", Some(20));
    assert_eq!(
        prepare_zk_prepared_persona_request(
            &wrong_profile,
            &WalletInvocationContext::ProtocolTransport,
            &id,
        )
        .err()
        .map(|error| error.reason()),
        Some(WalletErrorReason::ZkDerivationFailed)
    );
    assert_eq!(
        prepare_zk_prepared_persona_request(
            &request(
                "persona_credential_evidence_public_persona_v1",
                "first-nonce",
                None
            ),
            &WalletInvocationContext::ProtocolTransport,
            &id,
        )
        .err()
        .map(|error| error.reason()),
        Some(WalletErrorReason::ZkDerivationFailed)
    );
    let envelope = encode_zk_prepared_persona_response(&[1_u8; 32])
        .expect("bounded canonical bytes are transportable");
    assert!(parse_zk_prepared_persona_value(&envelope)
        .expect("transport roundtrip")
        .is_some());
}

#[test]
fn prepared_response_requires_live_verified_request_before_provider_disclosure() {
    let id = QueryId::parse("age").expect("fixture id");
    let verified = request(
        "persona_credential_evidence_public_persona_v1",
        "first-nonce",
        Some(20),
    );
    let mut provider = PreparedProvider { calls: 0 };
    for invalid_time in [9, 20] {
        assert_eq!(
            prepare_zk_prepared_persona_response(
                &verified,
                &WalletInvocationContext::ProtocolTransport,
                &id,
                invalid_time,
                &mut provider,
            )
            .err()
            .map(|error| error.reason()),
            Some(WalletErrorReason::ZkDerivationFailed)
        );
    }
    assert_eq!(provider.calls, 0);
    let response = prepare_zk_prepared_persona_response(
        &verified,
        &WalletInvocationContext::ProtocolTransport,
        &id,
        10,
        &mut provider,
    )
    .expect("authenticated request reaches provider");
    assert_eq!(provider.calls, 1);
    assert!(parse_zk_prepared_persona_value(&response)
        .expect("bounded transport")
        .is_some());
}

#[test]
fn unsigned_dc_api_prepared_response_uses_browser_origin_and_separate_time_hint() {
    let id = QueryId::parse("age").expect("fixture id");
    let mut raw = request(
        "persona_credential_evidence_public_persona_v1",
        "first-nonce",
        Some(20),
    )
    .request()
    .clone();
    raw.client_id = None;
    raw.response_mode = Some(ResponseMode::DcApiJwt);
    raw.response_uri = None;
    raw.state = None;
    let verified = validate_unsigned_dc_api_request(&raw).expect("browser request validates");
    let invocation = WalletInvocationContext::DigitalCredentialsApi(
        VerifiedPlatformOrigin::from_browser_security_context(
            "https://verifier.example".to_owned(),
        )
        .expect("canonical browser origin"),
    );
    let projected =
        prepare_zk_prepared_persona_unsigned_dc_api_request(&verified, &invocation, &id)
            .expect("separate time hint projects");
    assert_eq!(projected.issued_at_unix(), 10);
    assert_eq!(projected.expires_at_unix(), 20);
    assert_eq!(
        prepare_zk_prepared_persona_request(&verified, &invocation, &id)
            .err()
            .map(|error| error.reason()),
        Some(WalletErrorReason::ZkDerivationFailed)
    );
    let mut provider = PreparedProvider { calls: 0 };
    let response = prepare_zk_prepared_persona_unsigned_dc_api_response(
        &verified,
        &invocation,
        &id,
        10,
        &mut provider,
    )
    .expect("browser-bound response is prepared");
    assert_eq!(provider.calls, 1);
    assert!(parse_zk_prepared_persona_value(&response)
        .expect("bounded transport")
        .is_some());
    let mut without_hint = raw;
    without_hint.iat = None;
    let no_hint = validate_unsigned_dc_api_request(&without_hint)
        .expect("browser can pass request without time hint");
    assert_eq!(
        prepare_zk_prepared_persona_unsigned_dc_api_request(&no_hint, &invocation, &id)
            .err()
            .map(|error| error.reason()),
        Some(WalletErrorReason::ZkDerivationFailed)
    );
}
