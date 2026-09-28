// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical persistence encoding for hosted Request Object state.

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_proto_codec::{
    authorization_request_to_proto, decode_hosted_request_object_proto,
    encode_hosted_request_object_proto, proto_to_authorization_request,
};
use reallyme_openid4vp_verifier::CompactJwt;
use zeroize::Zeroizing;

use crate::{HostedRequestObject, RuntimeError, RuntimeErrorReason};

/// Encode hosted Request Object state using its schema-owned protobuf message.
pub fn encode_hosted_request_object(
    request_object: &HostedRequestObject,
) -> Result<Zeroizing<Vec<u8>>, RuntimeError> {
    let material = match request_object {
        HostedRequestObject::Signed { request_object_jwt } => {
            pb::hosted_request_object::Material::SignedRequestObjectJwt(
                request_object_jwt.as_str().to_owned(),
            )
        }
        HostedRequestObject::DeferredPost {
            authorization_request,
        } => pb::hosted_request_object::Material::DeferredPostAuthorizationRequest(Box::new(
            authorization_request_to_proto(authorization_request).map_err(|_| invalid_proto())?,
        )),
    };
    encode_hosted_request_object_proto(&pb::HostedRequestObject {
        material: Some(material),
        __buffa_unknown_fields: Default::default(),
    })
    .map_err(|_| invalid_proto())
}

/// Decode and validate schema-owned hosted Request Object state.
pub fn decode_hosted_request_object(bytes: &[u8]) -> Result<HostedRequestObject, RuntimeError> {
    let proto = decode_hosted_request_object_proto(bytes).map_err(|_| invalid_proto())?;
    match proto.material.as_ref() {
        Some(pb::hosted_request_object::Material::SignedRequestObjectJwt(jwt)) => {
            CompactJwt::new(jwt.clone())
                .map(HostedRequestObject::signed)
                .map_err(|_| invalid_proto())
        }
        Some(pb::hosted_request_object::Material::DeferredPostAuthorizationRequest(request)) => {
            let request = proto_to_authorization_request(request).map_err(|_| invalid_proto())?;
            HostedRequestObject::deferred_post(request)
        }
        None => Err(invalid_proto()),
    }
}

const fn invalid_proto() -> RuntimeError {
    RuntimeError::new(RuntimeErrorReason::InvalidProto)
}

#[cfg(test)]
#[path = "encode_hosted_request_object_tests.rs"]
mod tests;
