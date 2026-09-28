// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use std::sync::Arc;

use reallyme_openid4vp_types::ResponseMode;
use reallyme_openid4vp_verifier::BrowserSessionBinding;

use crate::build_problem_response::problem_http_response;
use crate::consume_verifier_session::VerifierSessionStore;
use crate::handle_direct_post::handle_direct_post_http;
use crate::handle_direct_post::DirectPostValidationContext;
use crate::handle_direct_post_jwt::handle_direct_post_jwt_http;
use crate::load_request_object::RequestObjectStore;
use crate::read_runtime_clock::RuntimeClock;
use crate::record_verifier_evidence::{
    VerifierEvidenceObservation, VerifierEvidenceObservationKind, VerifierEvidenceRecorder,
};
use crate::serve_request_object::{parse_request_object_retrieval, request_object_http_response};
use crate::{
    runtime_error_to_problem, ResponseCode, RuntimeError, RuntimeErrorReason, RuntimeHttpMethod,
    RuntimeHttpRequest, RuntimeHttpResponse, VerifierRuntimeService,
};

/// Runtime HTTP endpoint routed by the verifier host facade.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VerifierHttpEndpoint<'a> {
    /// Hosted `request_uri` Request Object endpoint.
    RequestObject {
        /// Adapter-defined Request Object lookup key.
        request_object_key: &'a str,
    },
    /// Plain `direct_post` response endpoint.
    DirectPost {
        /// Adapter-defined verifier session lookup key.
        session_key: &'a str,
    },
    /// Encrypted `direct_post.jwt` response endpoint.
    DirectPostJwt {
        /// Adapter-defined verifier session lookup key.
        session_key: &'a str,
    },
    /// Same-device follow-back endpoint reached by the initiating browser.
    FollowBack {
        /// One-time response code returned in the verifier redirect fragment.
        response_code: &'a ResponseCode,
        /// Authenticated host receipt for the current browser session.
        browser_session: &'a BrowserSessionBinding,
    },
}

impl fmt::Debug for VerifierHttpEndpoint<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::RequestObject { .. } => "RequestObject",
            Self::DirectPost { .. } => "DirectPost",
            Self::DirectPostJwt { .. } => "DirectPostJwt",
            Self::FollowBack { .. } => "FollowBack",
        };
        formatter
            .debug_struct("VerifierHttpEndpoint")
            .field("variant", &variant)
            .field("lookup_key", &"<redacted>")
            .finish()
    }
}

/// Framework-neutral verifier HTTP runtime host.
pub struct VerifierHttpRuntime {
    service: Arc<VerifierRuntimeService>,
    sessions: Arc<dyn VerifierSessionStore + Send + Sync>,
    request_objects: Arc<dyn RequestObjectStore>,
    clock: Arc<dyn RuntimeClock>,
    evidence_recorder: Option<Arc<dyn VerifierEvidenceRecorder>>,
    max_direct_post_body_bytes: usize,
}

impl VerifierHttpRuntime {
    /// Construct a verifier HTTP runtime host.
    pub fn new(
        service: Arc<VerifierRuntimeService>,
        sessions: Arc<dyn VerifierSessionStore + Send + Sync>,
        request_objects: Arc<dyn RequestObjectStore>,
        clock: Arc<dyn RuntimeClock>,
    ) -> Self {
        Self {
            service,
            sessions,
            request_objects,
            clock,
            evidence_recorder: None,
            max_direct_post_body_bytes: default_max_direct_post_body_bytes(),
        }
    }

    /// Override direct-post body-size policy.
    #[must_use]
    pub const fn with_max_direct_post_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_direct_post_body_bytes = max_body_bytes;
        self
    }

    /// Attach a durable observer used by certification and audit hosts.
    #[must_use]
    pub fn with_evidence_recorder(
        mut self,
        evidence_recorder: Arc<dyn VerifierEvidenceRecorder>,
    ) -> Self {
        self.evidence_recorder = Some(evidence_recorder);
        self
    }

    /// Route a framework-neutral HTTP request to the selected verifier endpoint.
    pub fn handle(
        &self,
        endpoint: VerifierHttpEndpoint<'_>,
        request: &RuntimeHttpRequest,
    ) -> RuntimeHttpResponse {
        match endpoint {
            VerifierHttpEndpoint::RequestObject { request_object_key } => {
                self.handle_request_object(request_object_key, request)
            }
            VerifierHttpEndpoint::DirectPost { session_key } => {
                self.handle_direct_post(session_key, request, DirectPostKind::Plain)
            }
            VerifierHttpEndpoint::DirectPostJwt { session_key } => {
                self.handle_direct_post(session_key, request, DirectPostKind::Jwt)
            }
            VerifierHttpEndpoint::FollowBack {
                response_code,
                browser_session,
            } => self.handle_follow_back(response_code, browser_session, request),
        }
    }

    fn handle_follow_back(
        &self,
        response_code: &ResponseCode,
        browser_session: &BrowserSessionBinding,
        request: &RuntimeHttpRequest,
    ) -> RuntimeHttpResponse {
        let response = self.try_handle_follow_back(response_code, browser_session, request);
        let response = match response {
            Ok(response) => response,
            Err(error) => problem_http_response(runtime_error_to_problem(error)),
        };
        self.record_response(
            response_code.as_str(),
            VerifierEvidenceObservationKind::FollowBackRedemption,
            response,
        )
    }

    fn try_handle_follow_back(
        &self,
        response_code: &ResponseCode,
        browser_session: &BrowserSessionBinding,
        request: &RuntimeHttpRequest,
    ) -> Result<RuntimeHttpResponse, RuntimeError> {
        if request.method != RuntimeHttpMethod::Post || !request.body.is_empty() {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod));
        }
        let now_unix = self.clock.now_unix()?;
        self.sessions
            .redeem_follow_back(response_code, browser_session, now_unix)?;
        Ok(RuntimeHttpResponse::empty(204).accepted())
    }

    fn handle_request_object(
        &self,
        request_object_key: &str,
        request: &RuntimeHttpRequest,
    ) -> RuntimeHttpResponse {
        let retrieval = match parse_request_object_retrieval(request) {
            Ok(retrieval) => retrieval,
            Err(error) => {
                return self.record_response(
                    request_object_key,
                    VerifierEvidenceObservationKind::RequestObjectRetrieval,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        let hosted = match self.request_objects.load_request_object(request_object_key) {
            Ok(hosted) => hosted,
            Err(error) => {
                return self.record_response(
                    request_object_key,
                    VerifierEvidenceObservationKind::RequestObjectRetrieval,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        let now_unix = match self.clock.now_unix() {
            Ok(now_unix) => now_unix,
            Err(error) => {
                return self.record_response(
                    request_object_key,
                    VerifierEvidenceObservationKind::RequestObjectRetrieval,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        // Metadata is validated and retained for the duration of this request.
        // The current preplanned Request Object does not negotiate optional
        // capabilities from it, but malformed metadata must still fail closed.
        let _validated_wallet_metadata = retrieval.wallet_metadata();
        let request_object_jwt = match self
            .service
            .materialize_request_object(&hosted, &retrieval, now_unix)
        {
            Ok(request_object_jwt) => request_object_jwt,
            Err(error) => {
                return self.record_response(
                    request_object_key,
                    VerifierEvidenceObservationKind::RequestObjectRetrieval,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        let response = match request_object_http_response(&request_object_jwt) {
            Ok(response) => response,
            Err(error) => problem_http_response(runtime_error_to_problem(error)),
        };
        self.record_response(
            request_object_key,
            VerifierEvidenceObservationKind::RequestObjectRetrieval,
            response,
        )
    }

    fn handle_direct_post(
        &self,
        session_key: &str,
        request: &RuntimeHttpRequest,
        kind: DirectPostKind,
    ) -> RuntimeHttpResponse {
        let observation_kind = match kind {
            DirectPostKind::Plain => VerifierEvidenceObservationKind::DirectPostValidation,
            DirectPostKind::Jwt => VerifierEvidenceObservationKind::DirectPostJwtValidation,
        };
        let session = match self.sessions.load_session(session_key) {
            Ok(session) => session,
            Err(error) => {
                return self.record_response(
                    session_key,
                    observation_kind,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        let expected_mode = match kind {
            DirectPostKind::Plain => ResponseMode::DirectPost,
            DirectPostKind::Jwt => ResponseMode::DirectPostJwt,
        };
        if session.response_mode != expected_mode {
            return self.record_response(
                session_key,
                observation_kind,
                problem_http_response(runtime_error_to_problem(crate::RuntimeError::new(
                    crate::RuntimeErrorReason::ResponseValidationFailed,
                ))),
            );
        }
        let now_unix = match self.clock.now_unix() {
            Ok(now_unix) => now_unix,
            Err(error) => {
                return self.record_response(
                    session_key,
                    observation_kind,
                    problem_http_response(runtime_error_to_problem(error)),
                )
            }
        };
        let context = DirectPostValidationContext::new(&session, now_unix)
            .with_max_body_bytes(self.max_direct_post_body_bytes)
            .with_response_decryption_key_id(session_key)
            .with_session_store(self.sessions.as_ref(), session_key);
        let response = match kind {
            DirectPostKind::Plain => handle_direct_post_http(&self.service, request, context),
            DirectPostKind::Jwt => handle_direct_post_jwt_http(&self.service, request, context),
        };
        self.record_response(session_key, observation_kind, response)
    }

    fn record_response(
        &self,
        lookup_key: &str,
        kind: VerifierEvidenceObservationKind,
        response: RuntimeHttpResponse,
    ) -> RuntimeHttpResponse {
        let Some(recorder) = self.evidence_recorder.as_ref() else {
            return response;
        };
        let observation = VerifierEvidenceObservation::from_disposition(
            kind,
            response.evidence_outcome,
            response.status,
        );
        if recorder
            .record_verifier_observation(lookup_key, observation)
            .is_err()
        {
            return problem_http_response(reallyme_openid4vp_types::ProblemDetails::from_kind(
                reallyme_openid4vp_types::ProblemKind::Internal,
            ));
        }
        response
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectPostKind {
    Plain,
    Jwt,
}

const fn default_max_direct_post_body_bytes() -> usize {
    128 * 1024
}

#[cfg(test)]
#[path = "route_verifier_http_tests.rs"]
mod tests;
