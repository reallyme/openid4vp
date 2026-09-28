// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::VerifierHttpEndpoint;

#[test]
fn endpoint_debug_redacts_lookup_keys() {
    let endpoint = VerifierHttpEndpoint::DirectPost {
        session_key: "sensitive-session-key",
    };

    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("sensitive-session-key"));
    assert!(debug.contains("DirectPost"));
}
