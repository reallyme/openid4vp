// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeMap;

use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::RequestUriMethod;
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;

use crate::report_proto_error::OpenId4VpProtoError;

/// Map wallet request transport classification into generated protobuf.
pub fn authorization_request_transport_to_proto(
    transport: &AuthorizationRequestTransport,
) -> pb::AuthorizationRequestTransport {
    let transport = match transport {
        AuthorizationRequestTransport::RequestJwt {
            jwt,
            expected_client_id,
            expected_wallet_nonce,
        } => Some(pb::authorization_request_transport::Transport::RequestJwt(
            Box::new(pb::RequestJwtTransport {
                jwt: jwt.clone(),
                expected_client_id: expected_client_id.clone(),
                expected_wallet_nonce: expected_wallet_nonce.clone(),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        AuthorizationRequestTransport::RequestUri {
            uri,
            method,
            wallet_nonce,
            expected_client_id,
        } => Some(pb::authorization_request_transport::Transport::RequestUri(
            Box::new(pb::RequestUriTransport {
                uri: uri.clone(),
                method: buffa::EnumValue::from(request_uri_method_to_proto(*method)),
                wallet_nonce: wallet_nonce.clone(),
                expected_client_id: expected_client_id.clone(),
                __buffa_unknown_fields: Default::default(),
            }),
        )),
        AuthorizationRequestTransport::InlineParams { params } => Some(
            pb::authorization_request_transport::Transport::InlineParams(Box::new(
                pb::InlineParamsTransport {
                    params: params
                        .iter()
                        .map(|(name, value)| pb::InlineParam {
                            name: name.clone(),
                            value: value.clone(),
                            __buffa_unknown_fields: Default::default(),
                        })
                        .collect(),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
        ),
    };
    pb::AuthorizationRequestTransport {
        transport,
        __buffa_unknown_fields: Default::default(),
    }
}

/// Map generated protobuf request transport into the wallet classification.
pub fn proto_to_authorization_request_transport(
    transport: &pb::AuthorizationRequestTransport,
) -> Result<AuthorizationRequestTransport, OpenId4VpProtoError> {
    let Some(transport) = transport.transport.as_ref() else {
        return Err(OpenId4VpProtoError::MissingField);
    };
    match transport {
        pb::authorization_request_transport::Transport::RequestJwt(value) => {
            Ok(AuthorizationRequestTransport::RequestJwt {
                jwt: value.jwt.clone(),
                expected_client_id: value.expected_client_id.clone(),
                expected_wallet_nonce: value.expected_wallet_nonce.clone(),
            })
        }
        pb::authorization_request_transport::Transport::RequestUri(value) => {
            Ok(AuthorizationRequestTransport::RequestUri {
                uri: value.uri.clone(),
                method: proto_to_request_uri_method(&value.method)?,
                wallet_nonce: value.wallet_nonce.clone(),
                expected_client_id: value.expected_client_id.clone(),
            })
        }
        pb::authorization_request_transport::Transport::InlineParams(value) => {
            let mut params = BTreeMap::new();
            for parameter in &value.params {
                if parameter.name.is_empty()
                    || params
                        .insert(parameter.name.clone(), parameter.value.clone())
                        .is_some()
                {
                    return Err(OpenId4VpProtoError::InvalidField);
                }
            }
            Ok(AuthorizationRequestTransport::InlineParams { params })
        }
    }
}

fn request_uri_method_to_proto(method: RequestUriMethod) -> pb::RequestUriMethod {
    match method {
        RequestUriMethod::Get => pb::RequestUriMethod::Get,
        RequestUriMethod::Post => pb::RequestUriMethod::Post,
    }
}

fn proto_to_request_uri_method(
    method: &buffa::EnumValue<pb::RequestUriMethod>,
) -> Result<RequestUriMethod, OpenId4VpProtoError> {
    match method.as_known() {
        Some(pb::RequestUriMethod::Get) => Ok(RequestUriMethod::Get),
        Some(pb::RequestUriMethod::Post) => Ok(RequestUriMethod::Post),
        Some(pb::RequestUriMethod::Unspecified) | None => {
            Err(OpenId4VpProtoError::InvalidEnumValue)
        }
    }
}
