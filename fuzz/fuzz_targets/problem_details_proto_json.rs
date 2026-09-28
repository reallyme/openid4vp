// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{openid4vp_proto_from_json, openid4vp_proto_to_json};

fuzz_target!(|data: &[u8]| {
    let Ok(json) = core::str::from_utf8(data) else {
        return;
    };
    let Ok(decoded) = openid4vp_proto_from_json::<pb::ProblemDetails>(json) else {
        return;
    };
    let Ok(encoded) = openid4vp_proto_to_json(&decoded) else {
        return;
    };
    let round_trip = openid4vp_proto_from_json::<pb::ProblemDetails>(&encoded);
    if round_trip.as_ref() != Ok(&decoded) {
        std::process::abort();
    }
});
