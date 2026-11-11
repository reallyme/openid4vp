// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(clippy::expect_used, reason = "bounded test fixture setup")]

use super::{VerifiedJsonClaims, MAX_VERIFIED_CLAIMS_DEPTH, MAX_VERIFIED_CLAIMS_JSON_BYTES};
use crate::VerifierErrorReason;
use serde_json::{json, Value};
use zeroize::Zeroize;

#[test]
fn authenticated_claims_are_redacted_and_explicitly_zeroizable() {
    let value = json!({"claim": "disclosure-fixture"});
    let mut claims = VerifiedJsonClaims::from_authenticated(value.clone())
        .expect("bounded authenticated fixture");
    assert_eq!(claims.as_value(), &value);
    assert!(!format!("{claims:?}").contains("disclosure-fixture"));
    claims.zeroize();
    assert_eq!(claims.as_value(), &Value::Null);
}

#[test]
fn authenticated_claims_reject_oversized_and_overdeep_projections() {
    let oversized = Value::String("a".repeat(MAX_VERIFIED_CLAIMS_JSON_BYTES));
    let mut nested = Value::Null;
    for _ in 0..=MAX_VERIFIED_CLAIMS_DEPTH {
        nested = Value::Array(vec![nested]);
    }
    for value in [oversized, nested] {
        let error = VerifiedJsonClaims::from_authenticated(value)
            .expect_err("projection exceeds its resource bound");
        assert_eq!(error.reason(), VerifierErrorReason::InvalidBinding);
    }
}
