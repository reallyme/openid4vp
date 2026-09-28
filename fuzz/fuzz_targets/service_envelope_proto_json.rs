// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    openid4vp_proto_from_json, openid4vp_proto_to_json, OpenId4VpProtoJson,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, json_bytes)) = data.split_first() else {
        return;
    };
    let Ok(json) = core::str::from_utf8(json_bytes) else {
        return;
    };

    match selector % 12 {
        0 => assert_round_trip::<pb::BuildAuthorizationRequestRequest>(json),
        1 => assert_round_trip::<pb::BuildAuthorizationRequestResponse>(json),
        2 => assert_round_trip::<pb::ValidateAuthorizationResponseRequest>(json),
        3 => assert_round_trip::<pb::ValidateAuthorizationResponseResponse>(json),
        4 => assert_round_trip::<pb::ParseAuthorizationRequestTransportRequest>(json),
        5 => assert_round_trip::<pb::ParseAuthorizationRequestTransportResponse>(json),
        6 => assert_round_trip::<pb::VerifyAuthorizationRequestRequest>(json),
        7 => assert_round_trip::<pb::VerifyAuthorizationRequestResponse>(json),
        8 => assert_round_trip::<pb::BuildDigitalCredentialRequestOptionsRequest>(json),
        9 => assert_round_trip::<pb::BuildDigitalCredentialRequestOptionsResponse>(json),
        10 => assert_round_trip::<pb::DecodeDcApiAuthorizationResponseRequest>(json),
        _ => assert_round_trip::<pb::DecodeDcApiAuthorizationResponseResponse>(json),
    }
});

fn assert_round_trip<M>(json: &str)
where
    M: OpenId4VpProtoJson + PartialEq + core::fmt::Debug,
{
    let Ok(decoded) = openid4vp_proto_from_json::<M>(json) else {
        return;
    };
    let Ok(encoded) = openid4vp_proto_to_json(&decoded) else {
        return;
    };
    let round_trip = openid4vp_proto_from_json::<M>(&encoded);
    if round_trip.as_ref() != Ok(&decoded) {
        std::process::abort();
    }
}
