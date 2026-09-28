// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dcql::DcqlQuery;

fuzz_target!(|data: &[u8]| {
    let _ = DcqlQuery::from_json_slice(data);
});
