// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

//! Integration tests for the SDK-facing root facade.

#[test]
#[cfg(feature = "codec")]
fn verify_sdk_facade_exposes_generated_proto_and_codec() {
    use reallyme_openid4vp::sdk::protobuf::proto::reallyme::openid4vp::v1 as pb;

    let fixture = include_str!("../../../vectors/protojson/problem-details.json");
    let decoded = reallyme_openid4vp::sdk::openid4vp_proto_from_json::<pb::ProblemDetails>(fixture);

    assert!(
        decoded.is_ok(),
        "facade generated ProtoJSON boundary is available"
    );
    let _problem = pb::ProblemDetails::default();
    let _stack_error = reallyme_openid4vp::sdk::error::IdentityStackError::default();
}

#[test]
fn verify_root_facade_exposes_sdk_policy() {
    let policy = reallyme_openid4vp::policy::OpenId4VpRequestPolicy::production();
    let wallet_policy = policy.wallet_transport_policy();

    assert!(wallet_policy.require_signed_request_object);
}

#[test]
#[cfg(feature = "runtime")]
fn verify_root_facade_exposes_runtime_wrapper() {
    let _service = reallyme_openid4vp::runtime::VerifierRuntimeService::new(
        reallyme_openid4vp::runtime::VerifierRuntimeConfig::new(),
    );

    let jwt = reallyme_openid4vp::verifier::CompactJwt::new("c2lnbmVk.cmVxdWVzdA.and0".to_owned())
        .expect("test compact JWT is structurally valid");
    let hosted = reallyme_openid4vp::runtime::HostedRequestObject::signed(jwt);

    assert!(matches!(
        hosted,
        reallyme_openid4vp::runtime::HostedRequestObject::Signed { .. }
    ));
    assert!(matches!(
        reallyme_openid4vp::runtime::VerifierHttpEndpoint::DirectPost {
            session_key: "session"
        },
        reallyme_openid4vp::runtime::VerifierHttpEndpoint::DirectPost { .. }
    ));
}

#[test]
#[cfg(all(feature = "runtime", feature = "codec"))]
fn verify_root_facade_exposes_proto_operations() {
    use reallyme_openid4vp::sdk::protobuf::proto::reallyme::openid4vp::v1 as pb;

    let service = reallyme_openid4vp::runtime::VerifierRuntimeService::new(
        reallyme_openid4vp::runtime::VerifierRuntimeConfig::new(),
    );
    let response =
        service.build_authorization_request_proto(&pb::BuildAuthorizationRequestRequest::default());

    assert!(response.problem.as_option().is_some());
}
