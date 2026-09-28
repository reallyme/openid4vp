// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto_codec::{decode_session_record, encode_session_record};

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = decode_session_record(data) {
        if let Ok(encoded) = encode_session_record(&record) {
            if decode_session_record(encoded.as_slice()).as_ref() != Ok(&record) {
                std::process::abort();
            }
        }
    }
});
