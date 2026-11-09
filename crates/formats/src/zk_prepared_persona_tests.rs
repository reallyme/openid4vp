// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![expect(
    clippy::expect_used,
    reason = "test assertions fail at the unexpected value"
)]

use reallyme_openid4vp_types::PresentationValue;
use serde_json::json;

use super::{
    encode_zk_prepared_persona_value, parse_zk_prepared_persona_value,
    MAX_ZK_PREPARED_PERSONA_BYTES, ZK_PREPARED_PERSONA_TYPE,
};
use crate::{is_zk_presentation_value, ZkFormatErrorReason};

#[test]
fn prepared_persona_transport_roundtrips_and_routes_as_zk() {
    let value =
        encode_zk_prepared_persona_value(&[1, 2, 3, 4]).expect("bounded canonical payload encodes");
    assert!(is_zk_presentation_value(&value));
    assert_eq!(
        parse_zk_prepared_persona_value(&value)
            .expect("canonical envelope parses")
            .expect("prepared marker is recognized")
            .as_slice(),
        &[1, 2, 3, 4]
    );
}

#[test]
fn prepared_persona_transport_rejects_malformed_or_oversized_payloads() {
    for value in [
        PresentationValue::Json(json!({"type": ZK_PREPARED_PERSONA_TYPE})),
        PresentationValue::Json(json!({"type": ZK_PREPARED_PERSONA_TYPE, "presentation_b64u": ""})),
        PresentationValue::Json(
            json!({"type": ZK_PREPARED_PERSONA_TYPE, "presentation_b64u": "AQ=="}),
        ),
        PresentationValue::Json(
            json!({"type": ZK_PREPARED_PERSONA_TYPE, "presentation_b64u": "AQ", "extra": true}),
        ),
        PresentationValue::Json(json!({"type": ZK_PREPARED_PERSONA_TYPE, "presentation_b64u": 1})),
    ] {
        assert_eq!(
            parse_zk_prepared_persona_value(&value)
                .expect_err("malformed envelope is rejected")
                .reason(),
            ZkFormatErrorReason::InvalidPresentationEncoding
        );
    }
    assert_eq!(
        encode_zk_prepared_persona_value(&vec![7; MAX_ZK_PREPARED_PERSONA_BYTES + 1])
            .expect_err("oversized protobuf is rejected")
            .reason(),
        ZkFormatErrorReason::InvalidPresentationEncoding
    );
}
