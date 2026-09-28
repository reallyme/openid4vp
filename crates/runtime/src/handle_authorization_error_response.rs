// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_direct_post_success_response::direct_post_success_response;
use crate::compare_secret::constant_time_str_eq;
use crate::handle_direct_post::DirectPostValidationContext;
use crate::parse_form_urlencoded::{optional_unique_field, required_unique_field, FormPair};
use crate::{RuntimeError, RuntimeErrorReason, RuntimeHttpResponse};

const ERROR_FIELD: &str = "error";
const RESPONSE_FIELD: &str = "response";
const STATE_FIELD: &str = "state";
const VP_TOKEN_FIELD: &str = "vp_token";

/// Return true when a form-urlencoded response body carries an OAuth error.
pub(crate) fn has_authorization_error(pairs: &[FormPair]) -> bool {
    pairs.iter().any(|pair| pair.key == ERROR_FIELD)
}

/// Process a wallet Authorization Error Response delivered to the Response URI.
pub(crate) fn handle_authorization_error_response(
    pairs: &[FormPair],
    context: &DirectPostValidationContext<'_>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let error = required_unique_field(pairs, ERROR_FIELD)?;
    validate_error_code(error)?;
    reject_mixed_success_and_error_response(pairs)?;

    let state = optional_unique_field(pairs, STATE_FIELD)?;
    if let Some(expected_state) = context.session.state.as_deref() {
        if !optional_secret_eq(state, Some(expected_state)) {
            return Err(RuntimeError::new(
                RuntimeErrorReason::ResponseValidationFailed,
            ));
        }
    }

    // State is intentionally not treated as authentication: it is present in
    // the Request Object and may be learned by an unauthenticated retriever.
    // Error responses therefore acknowledge receipt without consuming the
    // one-time session or redirecting the browser to a verifier frontend.
    direct_post_success_response(None, None)
}

fn optional_secret_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_str_eq(left, right),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn reject_mixed_success_and_error_response(pairs: &[FormPair]) -> Result<(), RuntimeError> {
    if optional_unique_field(pairs, VP_TOKEN_FIELD)?.is_some()
        || optional_unique_field(pairs, RESPONSE_FIELD)?.is_some()
    {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    Ok(())
}

fn validate_error_code(error: &str) -> Result<(), RuntimeError> {
    if error.is_empty()
        || !error
            .bytes()
            .all(|byte| matches!(byte, b'\x21' | b'\x23'..=b'\x5B' | b'\x5D'..=b'\x7E'))
    {
        return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
    }
    Ok(())
}
