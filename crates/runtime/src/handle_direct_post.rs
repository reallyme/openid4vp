// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto_codec::decode_vp_token_json;
use reallyme_openid4vp_types::AuthorizationResponse;
use reallyme_openid4vp_verifier::NonAuthorizingResponseDiagnostics;
use reallyme_openid4vp_verifier::SessionRecord;

use crate::build_problem_response::problem_http_response;
use crate::define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
use crate::handle_authorization_error_response::{
    handle_authorization_error_response, has_authorization_error,
};
use crate::parse_form_urlencoded::{
    optional_unique_field, parse_form_urlencoded, required_unique_field,
};
use crate::serve_request_object::form_urlencoded_media_type;
use crate::serve_request_object::validate_content_type;
use crate::validate_authorization_response::validate_authorization_response_for_session;
use crate::{
    runtime_error_to_problem, ResponseCode, RuntimeError, RuntimeErrorReason, SessionReservation,
    VerifiedAuthorizationResponse, VerifiedAuthorizationResult, VerifierRuntimeService,
    VerifierSessionStore,
};

const DEFAULT_MAX_DIRECT_POST_BODY_BYTES: usize = 128 * 1024;
const VP_TOKEN_FIELD: &str = "vp_token";
const STATE_FIELD: &str = "state";

/// Validation context for a `direct_post` Authorization Response.
pub(crate) struct DirectPostValidationContext<'a> {
    /// Session state loaded by the HTTP adapter.
    pub session: &'a SessionRecord,
    /// Current Unix timestamp.
    pub now_unix: u64,
    /// Maximum accepted form body size.
    pub max_body_bytes: usize,
    /// Exact one-time route key used to select response decryption material.
    pub response_decryption_key_id: Option<&'a str>,
    session_store: Option<&'a dyn VerifierSessionStore>,
    session_key: Option<&'a str>,
}

impl<'a> DirectPostValidationContext<'a> {
    /// Build a validation context with default body-size policy.
    pub(crate) const fn new(session: &'a SessionRecord, now_unix: u64) -> Self {
        Self {
            session,
            now_unix,
            max_body_bytes: DEFAULT_MAX_DIRECT_POST_BODY_BYTES,
            response_decryption_key_id: None,
            session_store: None,
            session_key: None,
        }
    }

    /// Override maximum accepted form body size.
    #[must_use]
    pub(crate) const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Bind encrypted-response key selection to the hosted session route.
    #[must_use]
    pub(crate) const fn with_response_decryption_key_id(mut self, key_id: &'a str) -> Self {
        self.response_decryption_key_id = Some(key_id);
        self
    }

    /// Attach the durable reservation/commit store for this session route.
    #[must_use]
    pub(crate) const fn with_session_store(
        mut self,
        store: &'a dyn VerifierSessionStore,
        key: &'a str,
    ) -> Self {
        self.session_store = Some(store);
        self.session_key = Some(key);
        self
    }

    pub(crate) fn reserve_session(&self) -> Result<SessionReservation, RuntimeError> {
        let (Some(store), Some(key)) = (self.session_store, self.session_key) else {
            return Err(RuntimeError::new(
                RuntimeErrorReason::MissingVerifiedResponseStore,
            ));
        };
        let reservation = store.reserve_session(key)?;
        if reservation.session() != self.session {
            let release_result = store.release_session(key, &reservation);
            if release_result.is_err() {
                return Err(RuntimeError::new(RuntimeErrorReason::SessionReleaseFailed));
            }
            return Err(RuntimeError::new(RuntimeErrorReason::SessionConsumeFailed));
        }
        Ok(reservation)
    }

    pub(crate) fn release_session(
        &self,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        let (Some(store), Some(key)) = (self.session_store, self.session_key) else {
            return Err(RuntimeError::new(
                RuntimeErrorReason::MissingVerifiedResponseStore,
            ));
        };
        store.release_session(key, reservation)
    }

    pub(crate) fn commit_verified_response(
        &self,
        reservation: &SessionReservation,
        raw_inbound_body: &[u8],
        verified: NonAuthorizingResponseDiagnostics,
    ) -> Result<ResponseCode, RuntimeError> {
        let (Some(store), Some(key)) = (self.session_store, self.session_key) else {
            return Err(RuntimeError::new(
                RuntimeErrorReason::MissingVerifiedResponseStore,
            ));
        };
        let response_code = ResponseCode::generate()?;
        store.commit_verified_authorization_response(
            key,
            reservation,
            &response_code,
            VerifiedAuthorizationResponse::new(
                self.session,
                VerifiedAuthorizationResult::new(
                    raw_inbound_body,
                    verified.into_verified_presentations(),
                ),
            ),
        )?;
        Ok(response_code)
    }
}

/// Handle an OpenID4VP `direct_post` HTTP response.
pub(crate) fn handle_direct_post_http(
    service: &VerifierRuntimeService,
    request: &RuntimeHttpRequest,
    context: DirectPostValidationContext<'_>,
) -> RuntimeHttpResponse {
    match try_handle_direct_post_http(service, request, context) {
        Ok(response) => response,
        Err(error) => problem_http_response(runtime_error_to_problem(error)),
    }
}

fn try_handle_direct_post_http(
    service: &VerifierRuntimeService,
    request: &RuntimeHttpRequest,
    context: DirectPostValidationContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    if request.method != RuntimeHttpMethod::Post {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod));
    }
    validate_content_type(
        request.content_type.as_deref(),
        form_urlencoded_media_type(),
    )?;
    if request.body.len() > context.max_body_bytes {
        return Err(RuntimeError::new(RuntimeErrorReason::BodyTooLarge));
    }

    let pairs = parse_form_urlencoded(&request.body)?;
    if has_authorization_error(&pairs) {
        return handle_authorization_error_response(&pairs, &context);
    }

    let response = parse_direct_post_response_pairs(&pairs)?;
    let verified = validate_authorization_response_for_session(
        service,
        &response,
        context.session,
        context.now_unix,
    )?;
    let reservation = context.reserve_session()?;
    let response_code =
        match context.commit_verified_response(&reservation, &request.body, verified) {
            Ok(response_code) => response_code,
            Err(error) => {
                context.release_session(&reservation)?;
                return Err(error);
            }
        };
    crate::build_direct_post_success_response::direct_post_success_response(
        context.session.post_response_redirect_uri.as_ref(),
        Some(&response_code),
    )
    .map(RuntimeHttpResponse::accepted)
}

pub(crate) fn parse_direct_post_response_pairs(
    pairs: &[crate::parse_form_urlencoded::FormPair],
) -> Result<AuthorizationResponse, RuntimeError> {
    let vp_token = required_unique_field(pairs, VP_TOKEN_FIELD)?;
    let state = optional_unique_field(pairs, STATE_FIELD)?;
    let vp_token = decode_vp_token_json(vp_token.as_bytes())
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))?;
    Ok(AuthorizationResponse {
        vp_token,
        state: state.map(str::to_owned),
    })
}
