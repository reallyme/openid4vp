// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::response::EncryptedDcApiAuthorizationResponse;
use crate::DcApiErrorReason;

#[test]
fn rejects_empty_encrypted_response() {
    let result = EncryptedDcApiAuthorizationResponse::new(String::new());
    assert!(result.is_err(), "encrypted DC API response is required");
    let Err(err) = result else {
        return;
    };

    assert_eq!(err.reason(), DcApiErrorReason::EmptyValue);
}
