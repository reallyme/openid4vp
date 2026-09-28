// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    encode_hosted_request_object_proto, MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
};
use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_verifier::CompactJwt;

use super::{decode_hosted_request_object, encode_hosted_request_object};
use crate::HostedRequestObject;

#[test]
fn round_trips_signed_request_object() {
    let jwt =
        CompactJwt::new("c2lnbmVk.cmVxdWVzdA.and0".to_owned()).expect("test compact JWT is valid");
    let request = HostedRequestObject::signed(jwt);

    let encoded = encode_hosted_request_object(&request).expect("hosted request encodes");
    let decoded = decode_hosted_request_object(&encoded).expect("hosted request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn round_trips_deferred_post_request_object() {
    let authorization_request: AuthorizationRequestObject =
        serde_json::from_value(serde_json::json!({
            "client_id": "x509_hash:certificate-thumbprint",
            "response_type": "vp_token",
            "response_mode": "direct_post.jwt",
            "response_uri": "https://verifier.example/direct-post",
            "nonce": "request-nonce",
            "dcql_query": {
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["urn:eudi:pid:1"]}
                }]
            }
        }))
        .expect("test request is valid");
    let request = HostedRequestObject::deferred_post(authorization_request)
        .expect("test deferred request is valid");

    let encoded = encode_hosted_request_object(&request).expect("hosted request encodes");
    let decoded = decode_hosted_request_object(&encoded).expect("hosted request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn rejects_oversized_unknown_and_empty_messages() {
    let oversized = vec![0_u8; MAX_OPENID4VP_PROTO_MESSAGE_BYTES + 1];
    assert!(decode_hosted_request_object(&oversized).is_err());
    assert!(decode_hosted_request_object(&[0xfa, 0x07, 0x01, 0x00]).is_err());
    assert!(decode_hosted_request_object(&[]).is_err());
}

#[test]
fn rejects_corrupt_persisted_signed_request_objects() {
    for corrupt in [
        "header.payload",
        "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn",
    ] {
        let encoded = encode_hosted_request_object_proto(&pb::HostedRequestObject {
            material: Some(pb::hosted_request_object::Material::SignedRequestObjectJwt(
                corrupt.to_owned(),
            )),
            __buffa_unknown_fields: Default::default(),
        })
        .expect("corrupt fixture is valid protobuf");

        assert!(decode_hosted_request_object(&encoded).is_err());
    }
}
