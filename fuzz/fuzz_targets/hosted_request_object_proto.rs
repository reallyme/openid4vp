// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_runtime::{
    decode_hosted_request_object, encode_hosted_request_object,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(hosted) = decode_hosted_request_object(data) {
        if let Ok(encoded) = encode_hosted_request_object(&hosted) {
            if decode_hosted_request_object(encoded.as_slice()).is_err() {
                std::process::abort();
            }
        }
    }
});
