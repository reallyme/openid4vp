// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    digital_credential_request_options_to_proto, proto_to_digital_credential_request_options,
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialRequestOptions,
    JwsJsonGeneral, JwsJsonSignature,
};

#[test]
fn maps_multisigned_dc_api_request_options() {
    let signature = JwsJsonSignature::new("cHJvdGVjdGVk".to_owned(), "c2lnbmF0dXJl".to_owned())
        .expect("test signature is valid");
    let request = JwsJsonGeneral::new("cGF5bG9hZA".to_owned(), vec![signature])
        .expect("test JWS JSON is valid");
    let entry = DigitalCredentialGetRequest::new_multisigned_request_object(
        DcApiProtocol::v1(DcApiRequestKind::Multisigned),
        request,
    )
    .expect("test multi-signed DC API request is valid");
    let options = DigitalCredentialRequestOptions::new(vec![entry])
        .expect("test DC API request options are valid");

    let proto = digital_credential_request_options_to_proto(&options).expect("DC API options map");
    let mapped =
        proto_to_digital_credential_request_options(&proto).expect("DC API options map back");

    assert_eq!(mapped, options);
}
