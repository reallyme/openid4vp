// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_dc_api::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialRequestOptions,
};
use reallyme_openid4vp_types::AuthorizationRequestObject;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<DigitalCredentialRequestOptions>(data);
    let Ok(request) = serde_json::from_slice::<AuthorizationRequestObject>(data) else {
        return;
    };
    for kind in [
        DcApiRequestKind::Unsigned,
        DcApiRequestKind::Signed,
        DcApiRequestKind::Multisigned,
    ] {
        let _ = DigitalCredentialGetRequest::new(DcApiProtocol::v1(kind), request.clone());
    }
});
