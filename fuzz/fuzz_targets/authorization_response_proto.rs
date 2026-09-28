// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use buffa::Message;
use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_response_to_proto, proto_to_authorization_response,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(response) = pb::AuthorizationResponse::decode_from_slice(data) {
        if let Ok(model) = proto_to_authorization_response(&response) {
            if let Ok(encoded) = authorization_response_to_proto(&model) {
                let decoded = proto_to_authorization_response(&encoded);
                if decoded.as_ref() != Ok(&model) {
                    std::process::abort();
                }
            }
        }
    }
});
