// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime protobuf operations and HTTP adapters for OpenID4VP.

mod build_authorization_request_launch_response;
mod build_direct_post_success_response;
mod build_problem_response;
mod build_verifier_service;
mod compare_secret;
mod consume_verifier_session;
mod decrypt_authorization_response_jwt;
#[cfg(feature = "jose")]
mod decrypt_authorization_response_with_jose;
mod define_http_message;
mod encode_hosted_request_object;
mod handle_authorization_error_response;
mod handle_authorization_request_launch;
mod handle_dc_api_proto;
mod handle_direct_post;
mod handle_direct_post_jwt;
mod handle_verifier_proto;
mod load_request_object;
mod map_runtime_error_reason;
mod map_runtime_problem;
mod materialize_request_object;
mod parse_form_urlencoded;
mod prepare_authorization_request_launch;
mod read_runtime_clock;
mod record_verifier_evidence;
mod report_runtime_error;
mod route_verifier_http;
mod serve_request_object;
mod store_verified_authorization_response;
mod validate_authorization_response;
#[cfg(test)]
#[path = "verify_runtime_tests.rs"]
mod verify_runtime;

pub use build_authorization_request_launch_response::authorization_request_launch_response;
pub use build_verifier_service::{VerifierRuntimeConfig, VerifierRuntimeService};
pub use consume_verifier_session::{
    SessionReservation, VerifierSessionStore, SESSION_RESERVATION_ID_BYTES,
};
pub use decrypt_authorization_response_jwt::{
    AuthorizationResponseDecryptionContext, AuthorizationResponseJwtDecryptor,
};
#[cfg(feature = "jose")]
pub use decrypt_authorization_response_with_jose::{
    JoseAuthorizationResponseJwtDecryptor, SessionBoundDirectJweKeyResolver,
    SessionBoundJweContentEncryptionKeyResolver,
};
pub use define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
pub use encode_hosted_request_object::{
    decode_hosted_request_object, encode_hosted_request_object,
};
pub use handle_authorization_request_launch::{
    handle_authorization_request_launch_http, AuthorizationRequestLaunchHttpContext,
    AuthorizationRequestLaunchHttpRequest, AuthorizationRequestLaunchPlanner,
};
pub use load_request_object::{HostedRequestObject, RequestObjectStore};
pub use map_runtime_error_reason::{
    error_reason_code, error_reason_from_identity_stack_error, identity_stack_error_from_reason,
    proto_to_runtime_error_reason, runtime_error_reason_to_proto,
};
pub use map_runtime_problem::runtime_error_to_problem;
pub use prepare_authorization_request_launch::{
    AuthorizationRequestLaunch, AuthorizationRequestLaunchRequest, AuthorizationRequestLaunchStore,
    AuthorizationRequestLaunchStoreRecord, AuthorizationRequestParameter,
    AuthorizationRequestParameterName,
};
pub use read_runtime_clock::{RuntimeClock, SystemRuntimeClock};
pub use record_verifier_evidence::{
    VerifierEvidenceContext, VerifierEvidenceObservation, VerifierEvidenceObservationKind,
    VerifierEvidenceOutcome, VerifierEvidenceRecorder, VerifierEvidenceRecorderError,
    VerifierEvidenceRecorderErrorReason,
};
pub use report_runtime_error::{RuntimeError, RuntimeErrorReason};
pub use route_verifier_http::{VerifierHttpEndpoint, VerifierHttpRuntime};
pub use serve_request_object::serve_request_object_http;
pub use store_verified_authorization_response::{
    ResponseCode, VerifiedAuthorizationResponse, VerifiedAuthorizationResult,
    MAX_RESPONSE_CODE_CHARS, MIN_RESPONSE_CODE_CHARS,
};
