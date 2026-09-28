// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Golden generated ProtoJSON fixtures for SDK and platform binding parity.

#![allow(clippy::expect_used)]

use core::fmt::Debug;

use buffa::DecodeOptions;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    openid4vp_proto_from_json, openid4vp_proto_to_json, OpenId4VpProtoError, OpenId4VpProtoJson,
    MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
};

const GOLDEN_PROTO_RECURSION_LIMIT: u32 = 64;
const GOLDEN_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;

fn assert_golden_round_trip<M>(fixture: &str)
where
    M: OpenId4VpProtoJson + Debug + PartialEq,
{
    let decoded: M = openid4vp_proto_from_json(fixture).expect("golden ProtoJSON must decode");
    let encoded = openid4vp_proto_to_json(&decoded).expect("generated ProtoJSON must encode");
    let round_trip: M =
        openid4vp_proto_from_json(&encoded).expect("generated ProtoJSON must decode again");

    assert_eq!(round_trip, decoded);

    let fixture_value: serde_json::Value =
        serde_json::from_str(fixture).expect("golden fixture must be valid JSON");
    let encoded_value: serde_json::Value =
        serde_json::from_str(&encoded).expect("generated output must be valid JSON");
    assert_eq!(encoded_value, fixture_value);
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_fixture(fixture: &str) -> Vec<u8> {
    let digits: Vec<u8> = fixture
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let (chunks, remainder) = digits.as_chunks::<2>();
    assert!(remainder.is_empty(), "wire fixture must contain byte pairs");

    chunks
        .iter()
        .map(|pair| {
            let high = decode_hex_nibble(pair[0]).expect("wire fixture must contain hexadecimal");
            let low = decode_hex_nibble(pair[1]).expect("wire fixture must contain hexadecimal");
            high.checked_mul(16)
                .and_then(|value| value.checked_add(low))
                .expect("decoded hexadecimal byte must fit in u8")
        })
        .collect()
}

fn assert_wire_golden<M>(json_fixture: &str, wire_fixture: &str)
where
    M: OpenId4VpProtoJson + Debug + PartialEq,
{
    let from_json: M =
        openid4vp_proto_from_json(json_fixture).expect("golden ProtoJSON must decode");
    let expected_wire = decode_hex_fixture(wire_fixture);
    let max_bytes = u32::try_from(MAX_OPENID4VP_PROTO_MESSAGE_BYTES)
        .expect("the configured protobuf limit must fit in u32");
    let mut encoded_wire = Vec::new();
    from_json
        .try_encode_bounded(max_bytes, &mut encoded_wire)
        .expect("golden protobuf must encode within the configured boundary");
    assert_eq!(encoded_wire, expected_wire);

    let from_wire: M = DecodeOptions::new()
        .with_recursion_limit(GOLDEN_PROTO_RECURSION_LIMIT)
        .with_max_message_size(MAX_OPENID4VP_PROTO_MESSAGE_BYTES)
        .with_unknown_field_limit(GOLDEN_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(&expected_wire)
        .expect("golden protobuf must decode within the configured boundary");
    assert_eq!(from_wire, from_json);
}

#[test]
fn authorization_request_protojson_fixture_round_trips() {
    assert_golden_round_trip::<pb::AuthorizationRequest>(include_str!(
        "../../../vectors/protojson/authorization-request.json"
    ));
}

#[test]
fn authorization_response_protojson_fixture_round_trips() {
    assert_golden_round_trip::<pb::AuthorizationResponse>(include_str!(
        "../../../vectors/protojson/authorization-response.json"
    ));
}

#[test]
fn problem_details_protojson_fixture_round_trips() {
    assert_golden_round_trip::<pb::ProblemDetails>(include_str!(
        "../../../vectors/protojson/problem-details.json"
    ));
}

#[test]
fn dc_api_request_options_protojson_fixture_round_trips() {
    assert_golden_round_trip::<pb::DigitalCredentialRequestOptions>(include_str!(
        "../../../vectors/protojson/dc-api-request-options.json"
    ));
}

#[test]
fn runtime_service_envelope_protojson_fixture_round_trips() {
    assert_golden_round_trip::<pb::BuildAuthorizationRequestRequest>(include_str!(
        "../../../vectors/protojson/build-authorization-request.json"
    ));
    assert_golden_round_trip::<pb::ValidateAuthorizationResponseResponse>(include_str!(
        "../../../vectors/protojson/validate-authorization-response.json"
    ));
}

#[test]
fn protobuf_wire_fixtures_match_protojson_contracts() {
    assert_wire_golden::<pb::AuthorizationRequest>(
        include_str!("../../../vectors/protojson/authorization-request.json"),
        include_str!("../../../vectors/protobuf/authorization-request.pb.hex"),
    );
    assert_wire_golden::<pb::AuthorizationResponse>(
        include_str!("../../../vectors/protojson/authorization-response.json"),
        include_str!("../../../vectors/protobuf/authorization-response.pb.hex"),
    );
    assert_wire_golden::<pb::ProblemDetails>(
        include_str!("../../../vectors/protojson/problem-details.json"),
        include_str!("../../../vectors/protobuf/problem-details.pb.hex"),
    );
    assert_wire_golden::<pb::BuildAuthorizationRequestRequest>(
        include_str!("../../../vectors/protojson/build-authorization-request.json"),
        include_str!("../../../vectors/protobuf/build-authorization-request.pb.hex"),
    );
}

#[test]
fn duplicate_protojson_fields_fail_closed() {
    let error = openid4vp_proto_from_json::<pb::AuthorizationRequest>(include_str!(
        "../../../vectors/protojson/malicious-duplicate-field.json"
    ))
    .expect_err("duplicate generated ProtoJSON fields must be rejected");

    assert_eq!(error, OpenId4VpProtoError::JsonDeserialize);
}

#[test]
fn unknown_protojson_enum_names_fail_closed() {
    let error = openid4vp_proto_from_json::<pb::AuthorizationRequest>(include_str!(
        "../../../vectors/protojson/malicious-unknown-enum.json"
    ))
    .expect_err("unknown generated ProtoJSON enum names must be rejected");

    assert_eq!(error, OpenId4VpProtoError::JsonDeserialize);
}
