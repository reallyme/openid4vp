// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn maps_dc_api_request_options() {
    let request = AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    };
    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("test DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");

    let proto = digital_credential_request_options_to_proto(&options).expect("DC API options map");
    let mapped =
        proto_to_digital_credential_request_options(&proto).expect("DC API options map back");

    assert_eq!(mapped, options);
}
#[test]
fn rejects_dc_api_protocol_data_mismatch_in_proto() {
    let request = AuthorizationRequestObject {
        client_id: None,
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DcApi),
        response_uri: None,
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: dcql_query(),
        transaction_data: None,
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    };
    let entry =
        DigitalCredentialGetRequest::new(DcApiProtocol::v1(DcApiRequestKind::Unsigned), request)
            .expect("test DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");
    let mut proto =
        digital_credential_request_options_to_proto(&options).expect("DC API options map");
    proto.requests[0].protocol = "openid4vp-v1-signed".to_owned();

    proto_to_digital_credential_request_options(&proto)
        .expect_err("the protocol identifier must agree with the protobuf oneof");
}
