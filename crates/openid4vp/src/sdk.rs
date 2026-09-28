// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical generated-message SDK surface.
//!
//! Cross-language packages bind this module's protobuf contract and bounded
//! wire operations. Native Rust domain APIs remain available through the
//! crate's focused modules and are not cross-language DTO definitions.

/// Generated `reallyme.openid4vp.v1` protobuf bindings.
pub use reallyme_openid4vp_proto::generated as protobuf;
pub use reallyme_openid4vp_proto_codec::{
    decode_operation_response_v1, execute_operation_json_v1, execute_operation_request,
    execute_operation_v1, openid4vp_proto_from_json, openid4vp_proto_to_json,
    OpenId4VpOperationKind, OpenId4VpProtoError, OpenId4VpProtoJson,
    MAX_OPENID4VP_OPERATION_RESPONSE_BYTES, MAX_OPENID4VP_OPERATION_RESPONSE_OVERHEAD_BYTES,
    MAX_OPENID4VP_PROTO_JSON_BYTES, MAX_OPENID4VP_PROTO_MESSAGE_BYTES,
};

/// Canonical typed error contracts shared by Rust and platform facades.
pub mod error {
    pub use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1::OpenId4VpErrorReason;
    pub use reallyme_openid4vp_proto_codec::{
        error_reason_code, error_reason_from_i32, error_reason_from_identity_stack_error,
        identity_stack_error_from_reason, proto_error_reason_to_proto,
    };
    pub use reallyme_ssi_proto::generated::proto::reallyme::identity::common::v1::{
        IdentityStackError, IdentityStackErrorDomain,
    };
}
