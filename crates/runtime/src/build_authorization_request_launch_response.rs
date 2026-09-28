// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto_codec::encode_bounded_json;
use reallyme_openid4vp_types::JSON_MEDIA_TYPE;
use serde::Serialize;

use crate::{AuthorizationRequestLaunch, RuntimeError, RuntimeErrorReason, RuntimeHttpResponse};

const MAX_LAUNCH_RESPONSE_JSON_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
struct AuthorizationRequestLaunchResponseJson<'a> {
    authorization_endpoint: &'a str,
    parameters: Vec<AuthorizationRequestParameterJson<'a>>,
}

#[derive(Serialize)]
struct AuthorizationRequestParameterJson<'a> {
    name: &'a str,
    value: &'a str,
}

/// Build the JSON response body consumed by the OIDF verifier flow driver.
pub fn authorization_request_launch_response(
    launch: &AuthorizationRequestLaunch,
) -> Result<RuntimeHttpResponse, RuntimeError> {
    let parameters = launch
        .parameters
        .iter()
        .map(|parameter| AuthorizationRequestParameterJson {
            name: parameter.name.as_str(),
            value: &parameter.value,
        })
        .collect::<Vec<_>>();
    let body = AuthorizationRequestLaunchResponseJson {
        authorization_endpoint: &launch.authorization_endpoint,
        parameters,
    };
    let mut encoded = encode_bounded_json(&body, MAX_LAUNCH_RESPONSE_JSON_BYTES)
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::LaunchEncodingFailed))?;
    Ok(
        RuntimeHttpResponse::with_body(200, JSON_MEDIA_TYPE, core::mem::take(&mut *encoded))
            .with_cache_control("no-store"),
    )
}
