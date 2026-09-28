// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Buffa protobuf transport mappings for OpenID4VP.
//!
//! Protobuf is the primary transport boundary. JSON helpers serialize and parse
//! the generated protobuf JSON shape; they do not define a second wire model.

mod convert;
mod encode_message;
mod map_authorization_request_transport;
mod map_authorization_response;
mod map_client_identifier;
mod map_dc_api;
mod map_error_reason;
mod map_problem_details;
mod map_session_binding;
mod map_vp_token_json;
mod operation;
mod report_proto_error;
mod sensitive_json;

pub use convert::{authorization_request_to_proto, proto_to_authorization_request};
pub use encode_message::{
    authorization_request_json_to_proto, authorization_request_proto_to_json,
    authorization_response_json_to_proto, authorization_response_proto_to_json,
    decode_authorization_request, decode_authorization_request_proto,
    decode_authorization_response, decode_authorization_response_proto,
    decode_hosted_request_object_proto, decode_session_record, encode_authorization_request,
    encode_authorization_request_proto, encode_authorization_response,
    encode_authorization_response_proto, encode_hosted_request_object_proto, encode_session_record,
    openid4vp_proto_from_json, openid4vp_proto_to_json, OpenId4VpProtoJson,
    MAX_OPENID4VP_PROTO_JSON_BYTES, MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
};
pub use map_authorization_request_transport::{
    authorization_request_transport_to_proto, proto_to_authorization_request_transport,
};
pub use map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
pub use map_client_identifier::{client_identifier_to_proto, proto_to_client_identifier};
pub use map_dc_api::{
    dc_api_authorization_response_to_proto, dc_api_protocol_to_proto,
    digital_credential_get_request_to_proto, digital_credential_request_options_to_proto,
    encrypted_dc_api_authorization_response_to_proto, proto_to_dc_api_authorization_response,
    proto_to_dc_api_protocol, proto_to_digital_credential_get_request,
    proto_to_digital_credential_request_options, proto_to_encrypted_dc_api_authorization_response,
};
pub use map_error_reason::{
    dc_api_error_reason_to_proto, dcql_error_reason_to_proto, error_reason_code,
    error_reason_from_enum_value, error_reason_from_i32, error_reason_from_identity_stack_error,
    error_reason_to_problem_kind, identity_stack_error_from_reason, problem_kind_to_error_reason,
    proto_error_reason_to_proto, proto_to_dc_api_error_reason, proto_to_dcql_error_reason,
    proto_to_proto_error_reason, proto_to_type_error_reason, proto_to_verifier_error_reason,
    proto_to_wallet_error_reason, proto_to_zk_error_reason, type_error_reason_to_proto,
    verifier_error_reason_to_proto, wallet_error_reason_to_proto, zk_error_reason_to_proto,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use map_error_reason::{mdoc_error_reason_to_proto, proto_to_mdoc_error_reason};
pub use map_problem_details::{problem_details_to_proto, proto_to_problem_details};
pub use map_session_binding::{
    holder_binding_claims_to_proto, proto_to_holder_binding_claims, proto_to_request_binding,
    proto_to_session_record, request_binding_to_proto, session_record_to_proto,
};
pub use map_vp_token_json::decode_vp_token_json;
pub use operation::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_request,
    execute_operation_v1, OpenId4VpOperationKind, MAX_OPENID4VP_OPERATION_RESPONSE_BYTES,
    MAX_OPENID4VP_OPERATION_RESPONSE_OVERHEAD_BYTES,
};
pub use report_proto_error::OpenId4VpProtoError;
pub use sensitive_json::{
    decode_bounded_json, encode_bounded_json, MAX_CLIENT_METADATA_JSON_BYTES, MAX_DCQL_JSON_BYTES,
    MAX_PRESENTATION_JSON_BYTES, MAX_SENSITIVE_JSON_NESTING_DEPTH, MAX_TRANSACTION_DATA_JSON_BYTES,
};
