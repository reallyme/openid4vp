// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto_codec::{execute_operation_json_v1, execute_operation_v1};

fuzz_target!(|data: &[u8]| {
    // Both platform entry points accept attacker-controlled bytes and must
    // always return a bounded typed response rather than unwind.
    let _binary_response = execute_operation_v1(data);
    let _json_response = execute_operation_json_v1(data);
});
