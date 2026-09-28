// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{encode_bounded_json, problem_details_to_proto};
use reallyme_openid4vp_types::{ProblemDetails, PROBLEM_JSON_MEDIA_TYPE};

use crate::RuntimeHttpResponse;

const INTERNAL_PROBLEM_JSON: &[u8] = br#"{"type":"https://really.me/problems/internal","title":"Internal server error","status":500,"kind":"Internal"}"#;
const MAX_PROBLEM_JSON_BYTES: usize = 16 * 1024;

pub(crate) fn problem_proto_http_response(problem: &pb::ProblemDetails) -> RuntimeHttpResponse {
    let status = problem_status(problem.status);
    let body = match encode_bounded_json(problem, MAX_PROBLEM_JSON_BYTES) {
        Ok(mut body) => core::mem::take(&mut *body),
        Err(_error) => INTERNAL_PROBLEM_JSON.to_vec(),
    };
    RuntimeHttpResponse::with_body(status, PROBLEM_JSON_MEDIA_TYPE, body)
}

pub(crate) fn problem_http_response(problem: ProblemDetails) -> RuntimeHttpResponse {
    problem_proto_http_response(&problem_details_to_proto(&problem))
}

fn problem_status(status: u32) -> u16 {
    u16::try_from(status).unwrap_or(500)
}
