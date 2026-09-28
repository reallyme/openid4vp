// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_problem_response::problem_http_response;
use crate::define_http_message::{RuntimeHttpMethod, RuntimeHttpRequest, RuntimeHttpResponse};
use crate::handle_authorization_error_response::{
    handle_authorization_error_response, has_authorization_error,
};
use crate::handle_direct_post::DirectPostValidationContext;
use crate::parse_form_urlencoded::{parse_form_urlencoded, required_unique_field, FormPair};
use crate::serve_request_object::form_urlencoded_media_type;
use crate::serve_request_object::validate_content_type;
use crate::validate_authorization_response::validate_authorization_response_for_session;
use crate::{
    runtime_error_to_problem, AuthorizationResponseDecryptionContext, RuntimeError,
    RuntimeErrorReason, VerifierRuntimeService,
};
use reallyme_codec::base64url::base64url_to_bytes;

const RESPONSE_FIELD: &str = "response";

/// Handle an OpenID4VP `direct_post.jwt` HTTP response.
///
/// OpenID4VP 1.0 defines this as `direct_post` plus a form field named
/// `response` containing an unsigned encrypted JWT/JWE. If a Wallet cannot
/// encrypt it can still send a normal `direct_post` error response; this
/// Error responses remain unencrypted as required by the protocol, while every
/// successful response must use the encrypted `response` field. Accepting a
/// plaintext `vp_token` here would silently downgrade verifier policy.
pub(crate) fn handle_direct_post_jwt_http(
    service: &VerifierRuntimeService,
    request: &RuntimeHttpRequest,
    context: DirectPostValidationContext<'_>,
) -> RuntimeHttpResponse {
    match try_handle_direct_post_jwt_http(service, request, context) {
        Ok(response) => response,
        Err(error) => problem_http_response(runtime_error_to_problem(error)),
    }
}

fn try_handle_direct_post_jwt_http(
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
    if has_response_field(&pairs) {
        return handle_encrypted_response(service, &pairs, &request.body, context);
    }

    Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt))
}

fn handle_encrypted_response(
    service: &VerifierRuntimeService,
    pairs: &[FormPair],
    raw_inbound_body: &[u8],
    context: DirectPostValidationContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let jwt = required_unique_field(pairs, RESPONSE_FIELD)?;
    validate_compact_jwe(jwt)?;
    let Some(decryptor) = service.response_jwt_decryptor() else {
        return Err(RuntimeError::new(
            RuntimeErrorReason::MissingResponseJwtDecryptor,
        ));
    };
    let decryption_context = context
        .response_decryption_key_id
        .map_or_else(AuthorizationResponseDecryptionContext::platform, |key_id| {
            AuthorizationResponseDecryptionContext::direct_post(key_id)
        });
    let reservation = context.reserve_session()?;
    let response = match decryptor.decrypt_authorization_response_jwt(jwt, decryption_context) {
        Ok(response) => response,
        Err(error) => {
            context.release_session(&reservation)?;
            return Err(error);
        }
    };
    let verified = match validate_authorization_response_for_session(
        service,
        &response,
        context.session,
        context.now_unix,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            context.release_session(&reservation)?;
            return Err(error);
        }
    };
    let response_code =
        match context.commit_verified_response(&reservation, raw_inbound_body, verified) {
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

fn has_response_field(pairs: &[FormPair]) -> bool {
    pairs.iter().any(|pair| pair.key == RESPONSE_FIELD)
}

fn validate_compact_jwe(jwt: &str) -> Result<(), RuntimeError> {
    if jwt.is_empty() || jwt.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt));
    }

    let mut segment_count = 0usize;
    for (index, segment) in jwt.split('.').enumerate() {
        if index > 4 {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt));
        }
        if segment.is_empty() && index != 1 {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt));
        }
        validate_base64url_segment(segment)?;
        segment_count = segment_count
            .checked_add(1)
            .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt))?;
    }

    if segment_count != 5 {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt));
    }

    Ok(())
}

fn validate_base64url_segment(segment: &str) -> Result<(), RuntimeError> {
    base64url_to_bytes(segment)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidResponseJwt))?;
    Ok(())
}
