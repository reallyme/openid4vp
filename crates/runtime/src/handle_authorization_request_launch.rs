// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_proto_codec::decode_bounded_json;
use reallyme_openid4vp_types::JSON_MEDIA_TYPE;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::build_authorization_request_launch_response::authorization_request_launch_response;
use crate::build_problem_response::problem_http_response;
use crate::record_verifier_evidence::validate_verifier_evidence_identifier;
use crate::serve_request_object::validate_content_type;
use crate::{
    runtime_error_to_problem, AuthorizationRequestLaunchRequest, AuthorizationRequestLaunchStore,
    RuntimeError, RuntimeErrorReason, RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse,
    VerifierRuntimeService,
};

const DEFAULT_MAX_LAUNCH_BODY_BYTES: usize = 16 * 1024;

/// Parsed request from the OIDF verifier flow driver.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationRequestLaunchHttpRequest {
    /// OIDF mock wallet authorization endpoint.
    pub authorization_endpoint: String,
    /// OIDF module id.
    pub module_id: String,
    /// OIDF test plan id selected by the pinned runner matrix.
    pub plan_id: String,
    /// Certification profile id selected by the pinned runner matrix.
    pub profile_id: String,
    /// OIDF module name exposed by the suite.
    pub module_name: String,
}

impl fmt::Debug for AuthorizationRequestLaunchHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestLaunchHttpRequest")
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for AuthorizationRequestLaunchHttpRequest {
    fn zeroize(&mut self) {
        self.authorization_endpoint.zeroize();
        self.module_id.zeroize();
        self.plan_id.zeroize();
        self.profile_id.zeroize();
        self.module_name.zeroize();
    }
}

impl Drop for AuthorizationRequestLaunchHttpRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestLaunchHttpRequest {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRequestLaunchJson {
    authorization_endpoint: String,
    module_id: String,
    plan_id: String,
    profile_id: String,
    module_name: String,
}

/// Host-owned planner for conformance verifier launch requests.
///
/// The runtime validates transport shape and signs/stores the resulting request,
/// but host policy decides the DCQL query, client identifier prefix, session
/// keys, request_uri, response_uri, and metadata for each conformance module.
pub trait AuthorizationRequestLaunchPlanner: Send + Sync {
    /// Build a final OpenID4VP launch request from the OIDF module context.
    fn plan_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchHttpRequest,
    ) -> Result<AuthorizationRequestLaunchRequest, RuntimeError>;

    /// Roll back provider-owned ephemeral material after launch preparation fails.
    ///
    /// The runtime invokes this after signing or atomic persistence fails. The
    /// operation must be idempotent because a store failure does not prove
    /// whether the backend began and rolled back its own transaction.
    fn cancel_authorization_request_launch(&self, session_key: &str) -> Result<(), RuntimeError>;
}

/// Dependencies for the framework-neutral launch endpoint.
pub struct AuthorizationRequestLaunchHttpContext<'a> {
    /// Runtime verifier service with signer and policy dependencies.
    pub service: &'a VerifierRuntimeService,
    /// Host launch planner.
    pub planner: &'a dyn AuthorizationRequestLaunchPlanner,
    /// Atomic host store for session and hosted Request Object material.
    pub store: &'a dyn AuthorizationRequestLaunchStore,
    /// Current Unix timestamp.
    pub now_unix: u64,
    /// Maximum accepted JSON body size.
    pub max_body_bytes: usize,
}

impl<'a> AuthorizationRequestLaunchHttpContext<'a> {
    /// Build a launch context with default body-size policy.
    pub const fn new(
        service: &'a VerifierRuntimeService,
        planner: &'a dyn AuthorizationRequestLaunchPlanner,
        store: &'a dyn AuthorizationRequestLaunchStore,
        now_unix: u64,
    ) -> Self {
        Self {
            service,
            planner,
            store,
            now_unix,
            max_body_bytes: DEFAULT_MAX_LAUNCH_BODY_BYTES,
        }
    }

    /// Override maximum accepted JSON body size.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// Handle the conformance-only verifier launch endpoint.
pub fn handle_authorization_request_launch_http(
    request: &RuntimeHttpRequest,
    context: AuthorizationRequestLaunchHttpContext<'_>,
) -> RuntimeHttpResponse {
    match try_handle_authorization_request_launch_http(request, context) {
        Ok(response) => response,
        Err(error) => problem_http_response(runtime_error_to_problem(error)),
    }
}

fn try_handle_authorization_request_launch_http(
    request: &RuntimeHttpRequest,
    context: AuthorizationRequestLaunchHttpContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    if request.method != RuntimeHttpMethod::Post {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod));
    }
    validate_content_type(request.content_type.as_deref(), JSON_MEDIA_TYPE)?;
    if request.body.len() > context.max_body_bytes {
        return Err(RuntimeError::new(RuntimeErrorReason::BodyTooLarge));
    }
    let launch_request = parse_launch_http_request(&request.body)?;
    let planned = context
        .planner
        .plan_authorization_request_launch(&launch_request)?;
    let launch = match context.service.prepare_authorization_request_launch(
        &planned,
        context.store,
        context.now_unix,
    ) {
        Ok(launch) => launch,
        Err(error) => {
            context
                .planner
                .cancel_authorization_request_launch(&planned.session_key)?;
            return Err(error);
        }
    };
    authorization_request_launch_response(&launch)
}

fn parse_launch_http_request(
    body: &[u8],
) -> Result<AuthorizationRequestLaunchHttpRequest, RuntimeError> {
    let value: AuthorizationRequestLaunchJson =
        decode_bounded_json(body, DEFAULT_MAX_LAUNCH_BODY_BYTES)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))?;
    validate_required_launch_value(&value.authorization_endpoint)?;
    validate_launch_identifier(&value.module_id)?;
    validate_launch_identifier(&value.plan_id)?;
    validate_launch_identifier(&value.profile_id)?;
    validate_launch_identifier(&value.module_name)?;
    Ok(AuthorizationRequestLaunchHttpRequest {
        authorization_endpoint: value.authorization_endpoint,
        module_id: value.module_id,
        plan_id: value.plan_id,
        profile_id: value.profile_id,
        module_name: value.module_name,
    })
}

fn validate_required_launch_value(value: &str) -> Result<(), RuntimeError> {
    if value.is_empty() {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    Ok(())
}

fn validate_launch_identifier(value: &str) -> Result<(), RuntimeError> {
    validate_verifier_evidence_identifier(value)
}

#[cfg(test)]
#[path = "handle_authorization_request_launch_tests.rs"]
mod tests;
