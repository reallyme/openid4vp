// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1::__buffa::oneof::decode_dc_api_authorization_response_request::Response as DcApiResponseOneof;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, authorization_response_to_proto,
    dc_api_authorization_response_to_proto, encrypted_dc_api_authorization_response_to_proto,
    session_record_to_proto,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, ClientIdentifier, PresentationValue,
    RequestUriMethod, ResponseMode, ResponseType, JSON_MEDIA_TYPE, PROBLEM_JSON_MEDIA_TYPE,
    REQUEST_OBJECT_MEDIA_TYPE,
};
use reallyme_openid4vp_verifier::{
    BrowserSessionBinding, CompactJwt, FollowBackRequirement, HolderBindingClaims,
    HolderBindingVerificationContext, HolderBindingVerifier, RequestBinding, RequestObjectSigner,
    PostResponseRedirectUri, RetainedMdocSessionTranscript, SessionRecord, VerifiedDisclosureSet,
    VerifiedHolderBinding, VerifiedTrustProvenance, VerifierError,
};
use serde_json::{json, Map as JsonMap};

use crate::handle_direct_post::{handle_direct_post_http, DirectPostValidationContext};
use crate::handle_direct_post_jwt::handle_direct_post_jwt_http;
use crate::{
    authorization_request_launch_response, handle_authorization_request_launch_http,
    AuthorizationRequestLaunchHttpContext, AuthorizationRequestLaunchHttpRequest,
    AuthorizationRequestLaunchPlanner, AuthorizationRequestLaunchRequest,
    AuthorizationRequestLaunchStore, AuthorizationRequestLaunchStoreRecord,
    AuthorizationRequestParameterName, AuthorizationResponseDecryptionContext,
    AuthorizationResponseJwtDecryptor, HostedRequestObject, RequestObjectStore, ResponseCode,
    RuntimeClock, RuntimeError, RuntimeErrorReason, RuntimeHttpMethod, RuntimeHttpRequest,
    RuntimeHttpResponse, SessionReservation, VerifiedAuthorizationResponse,
    VerifiedAuthorizationResult, VerifierEvidenceContext, VerifierEvidenceObservation,
    VerifierEvidenceObservationKind, VerifierEvidenceOutcome, VerifierEvidenceRecorder,
    VerifierEvidenceRecorderError, VerifierEvidenceRecorderErrorReason, VerifierHttpEndpoint,
    VerifierHttpRuntime, VerifierRuntimeConfig, VerifierRuntimeService, VerifierSessionStore,
};

#[cfg(feature = "jose")]
use crate::JoseAuthorizationResponseJwtDecryptor;

#[cfg(feature = "jose")]
static TEST_JWE_KEY: [u8; 16] = [7u8; 16];
#[cfg(all(feature = "jose", feature = "native"))]
static TEST_P256_RECIPIENT_SECRET: [u8; 32] = [
    0x21, 0x4f, 0x8b, 0x6c, 0xa2, 0x9d, 0x33, 0x10, 0x95, 0x47, 0x66, 0x12, 0x72, 0x83, 0xaf, 0xee,
    0x0d, 0x19, 0x41, 0x5b, 0x7c, 0x22, 0xd4, 0x39, 0x51, 0x8a, 0xb0, 0x65, 0x2f, 0x91, 0xc3, 0x44,
];
#[cfg(all(feature = "jose", feature = "native"))]
static TEST_P256_EPHEMERAL_SECRET: [u8; 32] = [
    0x6a, 0x10, 0x45, 0xf2, 0x33, 0x9e, 0x80, 0x12, 0xab, 0x74, 0xc6, 0x28, 0xde, 0x91, 0x07, 0x5b,
    0x49, 0xef, 0x32, 0x18, 0x84, 0x2d, 0xbc, 0x60, 0x13, 0xa5, 0x77, 0xc9, 0x0e, 0x4b, 0x26, 0xd1,
];

struct FixtureSigner;
#[derive(Default)]
struct CapturingSigner {
    wallet_nonces: Mutex<Vec<Option<String>>>,
}
struct FixtureHolderBindingVerifier;
struct FixtureResponseJwtDecryptor;
struct SessionBoundResponseJwtDecryptor;
struct FixtureSessionStore {
    state: Mutex<FixtureAuthorizationState>,
}
struct FailingCommitSessionStore {
    inner: FixtureSessionStore,
}

enum FixtureAuthorizationState {
    Live(SessionRecord),
    Reserved(SessionRecord),
    Committed {
        session: SessionRecord,
        result: VerifiedAuthorizationResult,
        response_code: String,
        released: bool,
    },
}
struct FixtureRequestObjectStore;
struct SignedFixtureRequestObjectStore;
#[derive(Default)]
struct FixtureLaunchStore {
    records: Mutex<Vec<StoredLaunchRecord>>,
}
struct FixtureLaunchPlanner;
#[derive(Default)]
struct CapturingLaunchPlanner {
    cancellations: Mutex<Vec<String>>,
}
struct FailingLaunchStore;
struct FixtureClock;
struct FixedClock(u64);
#[derive(Default)]
struct FixtureEvidenceRecorder {
    records: Mutex<Vec<(String, VerifierEvidenceObservation)>>,
}
struct FailingEvidenceRecorder;
#[cfg(all(feature = "jose", feature = "native"))]
struct FixtureEcdhEsP256Resolver;

#[derive(Debug, Clone, PartialEq)]
struct StoredLaunchRecord {
    session_key: String,
    session: SessionRecord,
    request_object_key: String,
    request_object: HostedRequestObject,
    evidence_context: Option<VerifierEvidenceContext>,
}

impl RequestObjectSigner for FixtureSigner {
    fn sign_request_object(
        &self,
        _request: &AuthorizationRequestObject,
    ) -> Result<CompactJwt, VerifierError> {
        CompactJwt::new(valid_compact_jws().to_owned())
    }
}

impl RequestObjectSigner for CapturingSigner {
    fn sign_request_object(
        &self,
        request: &AuthorizationRequestObject,
    ) -> Result<CompactJwt, VerifierError> {
        self.wallet_nonces
            .lock()
            .expect("fixture signer lock is available")
            .push(request.wallet_nonce.clone());
        CompactJwt::new(valid_compact_jws().to_owned())
    }
}

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

impl AuthorizationResponseJwtDecryptor for FixtureResponseJwtDecryptor {
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
        _context: crate::AuthorizationResponseDecryptionContext<'_>,
    ) -> Result<AuthorizationResponse, RuntimeError> {
        if jwt == valid_compact_jwe() {
            return Ok(response("fedcba9876543210"));
        }
        Err(RuntimeError::new(
            RuntimeErrorReason::ResponseJwtDecryptionFailed,
        ))
    }
}

impl AuthorizationResponseJwtDecryptor for SessionBoundResponseJwtDecryptor {
    fn decrypt_authorization_response_jwt(
        &self,
        jwt: &str,
        context: AuthorizationResponseDecryptionContext<'_>,
    ) -> Result<AuthorizationResponse, RuntimeError> {
        if jwt == valid_compact_jwe()
            && context.direct_post_session_key() == Some("expected-session-key")
        {
            return Ok(response("fedcba9876543210"));
        }
        Err(RuntimeError::new(
            RuntimeErrorReason::ResponseJwtDecryptionFailed,
        ))
    }
}

#[cfg(all(feature = "jose", feature = "native"))]
impl crate::SessionBoundJweContentEncryptionKeyResolver for FixtureEcdhEsP256Resolver {
    fn resolve_session_content_encryption_key(
        &self,
        _context: AuthorizationResponseDecryptionContext<'_>,
        header: &reallyme_jose::jwe::CompactJweProtectedHeader,
        encrypted_key: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, reallyme_jose::jwe::JweError> {
        if header.alg != reallyme_jose::jwe::JweKeyManagementAlgorithm::EcdhEs
            || !encrypted_key.is_empty()
        {
            return Err(reallyme_jose::jwe::JweError::InvalidEncryptedKey);
        }

        let epk = header
            .epk
            .as_ref()
            .ok_or(reallyme_jose::jwe::JweError::MissingRequiredHeaderParameter)?;
        let public_key = p256_public_key_from_epk(epk)?;
        let shared_secret = reallyme_crypto::p256::derive_p256_shared_secret(
            &TEST_P256_RECIPIENT_SECRET,
            &public_key,
        )
        .map_err(|_| reallyme_jose::jwe::JweError::Decrypt)?;
        reallyme_jose::jwe::derive_ecdh_es_content_encryption_key(&shared_secret, header)
    }
}

impl FixtureSessionStore {
    fn new() -> Self {
        Self {
            state: Mutex::new(FixtureAuthorizationState::Live(session())),
        }
    }

    fn with_response_mode(response_mode: ResponseMode) -> Self {
        let mut value = session();
        value.response_mode = response_mode;
        Self {
            state: Mutex::new(FixtureAuthorizationState::Live(value)),
        }
    }

    fn with_follow_back(expires_unix: u64) -> Self {
        let mut value = session();
        value.post_response_redirect_uri = Some(
            PostResponseRedirectUri::parse("https://verifier.example/result".to_owned())
                .expect("test redirect is valid"),
        );
        value.follow_back_requirement = Some(
            FollowBackRequirement::new(BrowserSessionBinding::new([19_u8; 32]), expires_unix)
                .expect("test follow-back requirement is valid"),
        );
        Self {
            state: Mutex::new(FixtureAuthorizationState::Live(value)),
        }
    }

    fn pending_response_code(&self) -> Option<String> {
        let state = self.state.lock().ok()?;
        match &*state {
            FixtureAuthorizationState::Committed {
                response_code,
                released: false,
                ..
            } => Some(response_code.clone()),
            FixtureAuthorizationState::Live(_)
            | FixtureAuthorizationState::Reserved(_)
            | FixtureAuthorizationState::Committed { .. } => None,
        }
    }

    fn persisted_outcome(&self) -> Option<(SessionRecord, VerifiedAuthorizationResult, String)> {
        let state = self.state.lock().ok()?;
        match &*state {
            FixtureAuthorizationState::Committed {
                session,
                result,
                response_code,
                released: true,
            } => Some((session.clone(), result.clone(), response_code.clone())),
            FixtureAuthorizationState::Committed {
                released: false, ..
            } => None,
            FixtureAuthorizationState::Live(_) | FixtureAuthorizationState::Reserved(_) => None,
        }
    }
}

impl FailingCommitSessionStore {
    fn new() -> Self {
        Self {
            inner: FixtureSessionStore::new(),
        }
    }
}

impl VerifierSessionStore for FixtureSessionStore {
    fn load_session(&self, key: &str) -> Result<SessionRecord, RuntimeError> {
        if key != "session" {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionConsumeFailed))?;
        match &*state {
            FixtureAuthorizationState::Live(session)
            | FixtureAuthorizationState::Reserved(session) => Ok(session.clone()),
            FixtureAuthorizationState::Committed { .. } => Err(RuntimeError::new(
                RuntimeErrorReason::SessionAlreadyConsumed,
            )),
        }
    }

    fn reserve_session(&self, key: &str) -> Result<SessionReservation, RuntimeError> {
        if key != "session" {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionConsumeFailed))?;
        match &*state {
            FixtureAuthorizationState::Live(session) => {
                let reserved = session.clone();
                *state = FixtureAuthorizationState::Reserved(reserved.clone());
                Ok(SessionReservation::new(reserved, [7_u8; 32]))
            }
            FixtureAuthorizationState::Reserved(_) => Err(RuntimeError::new(
                RuntimeErrorReason::SessionReservationConflict,
            )),
            FixtureAuthorizationState::Committed { .. } => Err(RuntimeError::new(
                RuntimeErrorReason::SessionAlreadyConsumed,
            )),
        }
    }

    fn release_session(
        &self,
        key: &str,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        if key != "session" || reservation.reservation_id() != &[7_u8; 32] {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed))?;
        match &*state {
            FixtureAuthorizationState::Reserved(session) if session == reservation.session() => {
                *state = FixtureAuthorizationState::Live(session.clone());
                Ok(())
            }
            FixtureAuthorizationState::Live(_)
            | FixtureAuthorizationState::Reserved(_)
            | FixtureAuthorizationState::Committed { .. } => {
                Err(RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed))
            }
        }
    }

    fn commit_verified_authorization_response(
        &self,
        key: &str,
        reservation: &SessionReservation,
        response_code: &ResponseCode,
        result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError> {
        if key != "session" || reservation.reservation_id() != &[7_u8; 32] {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed));
        }
        if result.result().presentations().is_empty() {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed));
        }
        if response_code.as_str().len() < crate::MIN_RESPONSE_CODE_CHARS {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseCode));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::SessionCommitFailed))?;
        match &*state {
            FixtureAuthorizationState::Reserved(session)
                if session == reservation.session() && session == result.session() =>
            {
                *state = FixtureAuthorizationState::Committed {
                    session: session.clone(),
                    result: result.into_result(),
                    response_code: response_code.as_str().to_owned(),
                    released: session.follow_back_requirement.is_none(),
                };
                Ok(())
            }
            FixtureAuthorizationState::Live(_)
            | FixtureAuthorizationState::Reserved(_)
            | FixtureAuthorizationState::Committed { .. } => {
                Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed))
            }
        }
    }

    fn redeem_follow_back(
        &self,
        response_code: &ResponseCode,
        browser_session: &BrowserSessionBinding,
        now_unix: u64,
    ) -> Result<(), RuntimeError> {
        use subtle::ConstantTimeEq;

        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::FollowBackRedemptionFailed))?;
        let FixtureAuthorizationState::Committed {
            session,
            response_code: stored_code,
            released,
            ..
        } = &mut *state
        else {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        };
        if !bool::from(
            stored_code
                .as_bytes()
                .ct_eq(response_code.as_str().as_bytes()),
        ) {
            return Err(RuntimeError::new(RuntimeErrorReason::SessionNotFound));
        }
        if *released {
            return Err(RuntimeError::new(
                RuntimeErrorReason::FollowBackAlreadyRedeemed,
            ));
        }
        let Some(requirement) = session.follow_back_requirement.as_ref() else {
            return Err(RuntimeError::new(
                RuntimeErrorReason::InvalidFollowBackRequirement,
            ));
        };
        if now_unix > requirement.expires_unix() {
            return Err(RuntimeError::new(RuntimeErrorReason::FollowBackExpired));
        }
        if !bool::from(
            requirement
                .browser_session()
                .as_bytes()
                .ct_eq(browser_session.as_bytes()),
        ) {
            return Err(RuntimeError::new(
                RuntimeErrorReason::FollowBackSessionMismatch,
            ));
        }
        *released = true;
        Ok(())
    }
}

impl VerifierSessionStore for FailingCommitSessionStore {
    fn load_session(&self, key: &str) -> Result<SessionRecord, RuntimeError> {
        self.inner.load_session(key)
    }

    fn reserve_session(&self, key: &str) -> Result<SessionReservation, RuntimeError> {
        self.inner.reserve_session(key)
    }

    fn release_session(
        &self,
        key: &str,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        self.inner.release_session(key, reservation)
    }

    fn commit_verified_authorization_response(
        &self,
        _key: &str,
        _reservation: &SessionReservation,
        _response_code: &ResponseCode,
        _result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::SessionCommitFailed))
    }

    fn redeem_follow_back(
        &self,
        response_code: &ResponseCode,
        browser_session: &BrowserSessionBinding,
        now_unix: u64,
    ) -> Result<(), RuntimeError> {
        self.inner
            .redeem_follow_back(response_code, browser_session, now_unix)
    }
}

impl RequestObjectStore for FixtureRequestObjectStore {
    fn load_request_object(&self, key: &str) -> Result<HostedRequestObject, RuntimeError> {
        if key == "request" {
            return HostedRequestObject::deferred_post(authorization_request());
        }
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

impl RequestObjectStore for SignedFixtureRequestObjectStore {
    fn load_request_object(&self, key: &str) -> Result<HostedRequestObject, RuntimeError> {
        if key == "request" {
            let jwt = CompactJwt::new(valid_compact_jws().to_owned())
                .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
            return Ok(HostedRequestObject::signed(jwt));
        }
        Err(RuntimeError::new(RuntimeErrorReason::RequestObjectNotFound))
    }
}

impl AuthorizationRequestLaunchStore for FixtureLaunchStore {
    fn store_authorization_request_launch(
        &self,
        record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError> {
        let mut records = self
            .records
            .lock()
            .expect("fixture store lock is available");
        records.push(StoredLaunchRecord {
            session_key: record.session_key.to_owned(),
            session: record.session,
            request_object_key: record.request_object_key.to_owned(),
            request_object: record.request_object,
            evidence_context: record.evidence_context,
        });
        Ok(())
    }
}

impl AuthorizationRequestLaunchStore for FailingLaunchStore {
    fn store_authorization_request_launch(
        &self,
        _record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::LaunchStoreFailed))
    }
}

impl AuthorizationRequestLaunchPlanner for FixtureLaunchPlanner {
    fn plan_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchHttpRequest,
    ) -> Result<AuthorizationRequestLaunchRequest, RuntimeError> {
        let mut planned = authorization_launch_request();
        planned.authorization_endpoint = request.authorization_endpoint.clone();
        planned.session_key = request.module_id.clone();
        planned.request_object_key = request.module_id.clone();
        planned.request_uri = "https://verifier.example/request/module-1".to_owned();
        planned.evidence_context = Some(VerifierEvidenceContext::new(
            request.plan_id.clone(),
            request.profile_id.clone(),
            request.module_id.clone(),
            request.module_name.clone(),
        )?);
        Ok(planned)
    }

    fn cancel_authorization_request_launch(&self, _session_key: &str) -> Result<(), RuntimeError> {
        Ok(())
    }
}

impl AuthorizationRequestLaunchPlanner for CapturingLaunchPlanner {
    fn plan_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchHttpRequest,
    ) -> Result<AuthorizationRequestLaunchRequest, RuntimeError> {
        FixtureLaunchPlanner.plan_authorization_request_launch(request)
    }

    fn cancel_authorization_request_launch(&self, session_key: &str) -> Result<(), RuntimeError> {
        self.cancellations
            .lock()
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::LaunchStoreFailed))?
            .push(session_key.to_owned());
        Ok(())
    }
}

impl RuntimeClock for FixtureClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(10)
    }
}

impl RuntimeClock for FixedClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(self.0)
    }
}

impl VerifierEvidenceRecorder for FixtureEvidenceRecorder {
    fn record_verifier_observation(
        &self,
        lookup_key: &str,
        observation: VerifierEvidenceObservation,
    ) -> Result<(), VerifierEvidenceRecorderError> {
        let mut records = self.records.lock().map_err(|_| {
            VerifierEvidenceRecorderError::new(VerifierEvidenceRecorderErrorReason::Unavailable)
        })?;
        records.push((lookup_key.to_owned(), observation));
        Ok(())
    }
}

impl VerifierEvidenceRecorder for FailingEvidenceRecorder {
    fn record_verifier_observation(
        &self,
        _lookup_key: &str,
        _observation: VerifierEvidenceObservation,
    ) -> Result<(), VerifierEvidenceRecorderError> {
        Err(VerifierEvidenceRecorderError::new(
            VerifierEvidenceRecorderErrorReason::WriteFailed,
        ))
    }
}

fn valid_compact_jwe() -> &'static str {
    "eyJhbGciOiJFQ0RILUVTIn0..aXY.Yw.dGFn"
}

fn valid_compact_jws() -> &'static str {
    "c2lnbmVk.cmVxdWVzdA.and0"
}

fn serve_request_object_http(
    request: &RuntimeHttpRequest,
    _request_object_jwt: &str,
    expected_wallet_nonce: Option<&str>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let jwt = CompactJwt::new(valid_compact_jws().to_owned())
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
    crate::serve_request_object_http(request, &jwt, expected_wallet_nonce)
}

fn dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: QueryId::parse("pid").expect("test query id is valid"),
            format: CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned())
                .expect("test format is valid"),
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
    }
}

fn authorization_request() -> AuthorizationRequestObject {
    AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: None,
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        expected_origins: None,
        iss: Some("x509_san_dns:verifier.example".to_owned()),
        aud: Some(vec!["openid4vp://".to_owned()]),
        iat: Some(10),
        exp: Some(100),
    }
}

fn authorization_launch_request() -> AuthorizationRequestLaunchRequest {
    let mut request = authorization_request();
    request.response_mode = Some(ResponseMode::DirectPostJwt);
    request.response_uri = Some("https://verifier.example/direct_post.jwt/session-1".to_owned());
    AuthorizationRequestLaunchRequest {
        authorization_endpoint: "https://suite.example/test/a/module/authorize".to_owned(),
        authorization_request: request,
        session_key: "session-1".to_owned(),
        request_object_key: "request-1".to_owned(),
        request_uri: "https://verifier.example/request/request-1".to_owned(),
        request_uri_method: RequestUriMethod::Post,
        evidence_context: Some(
            VerifierEvidenceContext::new(
                "oid4vp-1final-verifier-haip-test-plan".to_owned(),
                "verifier-sd-jwt-vc-direct-post-jwt".to_owned(),
                "module-1".to_owned(),
                "oid4vp-1final-verifier-happy-flow".to_owned(),
            )
            .expect("test evidence context is valid"),
        ),
        mdoc_session_transcript: Some(
            RetainedMdocSessionTranscript::new(vec![0x83, 0xf6, 0xf6, 0x80])
                .expect("test transcript is bounded"),
        ),
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    }
}

fn build_request(sign_request_object: bool) -> pb::BuildAuthorizationRequestRequest {
    pb::BuildAuthorizationRequestRequest {
        request: buffa::MessageField::some(
            authorization_request_to_proto(&authorization_request())
                .expect("request maps to proto"),
        ),
        sign_request_object,
        now_unix: 11,
        __buffa_unknown_fields: Default::default(),
    }
}

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
        dcql_query: dcql_query(),
        response_mode: ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    }
}

fn response(state: &str) -> AuthorizationResponse {
    AuthorizationResponse::single(
        QueryId::parse("pid").expect("test query id is valid"),
        vec![PresentationValue::Compact("presentation".to_owned())],
        Some(state.to_owned()),
    )
    .expect("test response is valid")
}

fn config_with_holder_binding() -> VerifierRuntimeConfig {
    VerifierRuntimeConfig::new()
        .with_holder_binding_verifier(Arc::new(FixtureHolderBindingVerifier))
}

include!("verify_runtime_launch_tests.rs");
include!("verify_runtime_request_tests.rs");
include!("verify_runtime_jwt_tests.rs");
include!("verify_runtime_response_mode_tests.rs");
