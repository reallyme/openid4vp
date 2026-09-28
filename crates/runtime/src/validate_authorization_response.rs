// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::AuthorizationResponse;
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, NonAuthorizingResponseDiagnostics,
    ResponseValidationOptions, SessionRecord,
};

use crate::{RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

pub(crate) fn validate_authorization_response_for_session(
    service: &VerifierRuntimeService,
    response: &AuthorizationResponse,
    session: &SessionRecord,
    now_unix: u64,
) -> Result<NonAuthorizingResponseDiagnostics, RuntimeError> {
    match diagnose_authorization_response_with_options(
        session,
        response,
        now_unix,
        ResponseValidationOptions {
            holder_binding_verifier: service.holder_binding_verifier(),
        },
    ) {
        Ok(verified) => Ok(verified),
        Err(_) => Err(RuntimeError::new(
            RuntimeErrorReason::ResponseValidationFailed,
        )),
    }
}
