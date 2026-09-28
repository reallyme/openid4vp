// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use buffa::Message;
use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, proto_to_authorization_request,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = pb::AuthorizationRequest::decode_from_slice(data) {
        if let Ok(model) = proto_to_authorization_request(&request) {
            if let Ok(encoded) = authorization_request_to_proto(&model) {
                let decoded = proto_to_authorization_request(&encoded);
                if decoded.as_ref() != Ok(&model) {
                    std::process::abort();
                }
            }
        }
    }
});
