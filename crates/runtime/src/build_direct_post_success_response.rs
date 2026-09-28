// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::openid4vp_proto_to_json;
use reallyme_openid4vp_types::JSON_MEDIA_TYPE;
use reallyme_openid4vp_verifier::PostResponseRedirectUri;

use crate::{ResponseCode, RuntimeError, RuntimeErrorReason, RuntimeHttpResponse};

const RESPONSE_CODE_FRAGMENT_PREFIX: &str = "#response_code=";

/// Build the OpenID4VP response-endpoint success body.
pub(crate) fn direct_post_success_response(
    redirect_uri: Option<&PostResponseRedirectUri>,
    response_code: Option<&ResponseCode>,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let redirect_uri = match (redirect_uri, response_code) {
        (Some(redirect_uri), Some(response_code)) => Some(redirect_uri_with_response_code(
            redirect_uri,
            response_code,
        )?),
        // The protocol permits an empty success response when the verifier did
        // not request a redirect. The internally stored code is not disclosed.
        (None, _) => None,
        // A requested redirect without its one-time code would reopen the
        // session-fixation weakness this binding is intended to prevent.
        (Some(_), None) => {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidResponseCode));
        }
    };
    let body = openid4vp_proto_to_json(&pb::DirectPostSuccessResponse {
        redirect_uri,
        // OpenID4VP wallets navigate only to redirect_uri. A sibling extension
        // field is intentionally omitted because compliant wallets ignore it.
        response_code: None,
        __buffa_unknown_fields: Default::default(),
    })
    .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidProto))?;
    Ok(
        RuntimeHttpResponse::with_body(200, JSON_MEDIA_TYPE, body.as_bytes().to_vec())
            .with_cache_control("no-store"),
    )
}

fn redirect_uri_with_response_code(
    redirect_uri: &PostResponseRedirectUri,
    response_code: &ResponseCode,
) -> Result<String, RuntimeError> {
    let capacity = redirect_uri
        .as_str()
        .len()
        .checked_add(RESPONSE_CODE_FRAGMENT_PREFIX.len())
        .and_then(|length| length.checked_add(response_code.as_str().len()))
        .ok_or_else(|| RuntimeError::new(RuntimeErrorReason::InvalidResponseCode))?;
    let mut value = String::new();
    value
        .try_reserve_exact(capacity)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidResponseCode))?;
    value.push_str(redirect_uri.as_str());
    value.push_str(RESPONSE_CODE_FRAGMENT_PREFIX);
    value.push_str(response_code.as_str());
    Ok(value)
}

#[cfg(test)]
#[path = "build_direct_post_success_response_tests.rs"]
mod tests;
