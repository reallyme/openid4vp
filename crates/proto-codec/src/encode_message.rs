// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, Message};
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1 as pb;
use reallyme_openid4vp_types::{AuthorizationRequestObject, AuthorizationResponse};
use reallyme_openid4vp_verifier::SessionRecord;
use serde::de::DeserializeOwned;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserializer;
use std::cell::Cell;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

use crate::convert::{authorization_request_to_proto, proto_to_authorization_request};
use crate::map_authorization_response::{
    authorization_response_to_proto, proto_to_authorization_response,
};
use crate::map_session_binding::{proto_to_session_record, session_record_to_proto};
use crate::report_proto_error::OpenId4VpProtoError;

mod private {
    pub trait Sealed {}
}

/// Generated OpenID4VP messages approved for the public ProtoJSON boundary.
///
/// The trait is sealed so callers cannot route unrelated Serde types through
/// this codec and accidentally treat them as schema-owned OpenID4VP DTOs.
pub trait OpenId4VpProtoJson:
    Message + serde::Serialize + DeserializeOwned + private::Sealed
{
}

macro_rules! impl_openid4vp_proto_json {
    ($($message:path),+ $(,)?) => {
        $(
            impl private::Sealed for $message {}
            impl OpenId4VpProtoJson for $message {}
        )+
    };
}

impl_openid4vp_proto_json!(
    pb::AuthorizationRequest,
    pb::AuthorizationResponse,
    pb::AuthorizationRequestTransport,
    pb::ClientMetadata,
    pb::ProblemDetails,
    pb::DirectPostSuccessResponse,
    pb::DigitalCredentialRequestOptions,
    pb::DcApiAuthorizationResponse,
    pb::BuildAuthorizationRequestRequest,
    pb::BuildAuthorizationRequestResponse,
    pb::ValidateAuthorizationResponseRequest,
    pb::ValidateAuthorizationResponseResponse,
    pb::ParseAuthorizationRequestTransportRequest,
    pb::ParseAuthorizationRequestTransportResponse,
    pb::VerifyAuthorizationRequestRequest,
    pb::VerifyAuthorizationRequestResponse,
    pb::BuildDigitalCredentialRequestOptionsRequest,
    pb::BuildDigitalCredentialRequestOptionsResponse,
    pb::DecodeDcApiAuthorizationResponseRequest,
    pb::DecodeDcApiAuthorizationResponseResponse,
    pb::OpenId4VpOperationRequest,
    pb::OpenId4VpOperationResponse,
);

/// Maximum accepted OpenID4VP protobuf payload size at this codec boundary.
///
/// The cap is enforced before Buffa decoding so hostile length-delimited
/// payloads cannot force unbounded allocation in SDK, FFI, or service adapters.
pub const MAX_OPENID4VP_PROTO_MESSAGE_BYTES: usize = 2_097_152;

/// Maximum accepted/generated OpenID4VP protobuf JSON size at this boundary.
///
/// This allows base64 expansion of the protobuf byte cap while still keeping
/// JSON-only callers under a deterministic resource ceiling.
pub const MAX_OPENID4VP_PROTO_JSON_BYTES: usize = 3_145_728;

/// Maximum aggregate JSON array elements and object members accepted before
/// generated ProtoJSON deserialization allocates repeated-field storage.
pub const MAX_OPENID4VP_PROTO_JSON_ELEMENTS: usize = 65_536;

const OPENID4VP_PROTO_RECURSION_LIMIT: u32 = 64;
const OPENID4VP_PROTO_UNKNOWN_FIELD_LIMIT: usize = 0;

pub(crate) fn encode_generated_proto<M: Message>(
    message: &M,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    encode_generated_proto_with_limit(message, MAX_OPENID4VP_PROTO_MESSAGE_BYTES)
}

pub(crate) fn encode_generated_proto_with_limit<M: Message>(
    message: &M,
    max_message_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    let max_bytes = u32::try_from(max_message_bytes).map_err(|_| OpenId4VpProtoError::Encode)?;
    let mut bytes = Zeroizing::new(Vec::new());
    message
        .try_encode_bounded(max_bytes, &mut *bytes)
        .map_err(|_| OpenId4VpProtoError::Encode)?;
    Ok(bytes)
}

pub(crate) fn decode_generated_proto<M: Message>(bytes: &[u8]) -> Result<M, OpenId4VpProtoError> {
    decode_generated_proto_with_limit(bytes, MAX_OPENID4VP_PROTO_MESSAGE_BYTES)
}

pub(crate) fn decode_generated_proto_with_limit<M: Message>(
    bytes: &[u8],
    max_message_bytes: usize,
) -> Result<M, OpenId4VpProtoError> {
    if bytes.len() > max_message_bytes {
        return Err(OpenId4VpProtoError::Decode);
    }

    DecodeOptions::new()
        .with_recursion_limit(OPENID4VP_PROTO_RECURSION_LIMIT)
        .with_max_message_size(max_message_bytes)
        .with_unknown_field_limit(OPENID4VP_PROTO_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(bytes)
        .map_err(|_| OpenId4VpProtoError::Decode)
}

fn serialize_generated_json<M: serde::Serialize + Message>(
    message: &M,
) -> Result<Zeroizing<String>, OpenId4VpProtoError> {
    if !generated_proto_fits_message_budget(message) {
        return Err(OpenId4VpProtoError::JsonSerialize);
    }

    // Own the serializer buffer under Zeroizing from allocation onward so a
    // partial serialization or size rejection cannot leave claims in memory.
    let mut json_bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *json_bytes, message)
        .map_err(|_| OpenId4VpProtoError::JsonSerialize)?;
    if json_bytes.len() > MAX_OPENID4VP_PROTO_JSON_BYTES {
        return Err(OpenId4VpProtoError::JsonSerialize);
    }

    match String::from_utf8(core::mem::take(&mut *json_bytes)) {
        Ok(json) => Ok(Zeroizing::new(json)),
        Err(error) => {
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            Err(OpenId4VpProtoError::JsonSerialize)
        }
    }
}

/// Serialize an approved generated OpenID4VP message using Buffa ProtoJSON.
pub fn openid4vp_proto_to_json<M: OpenId4VpProtoJson>(
    message: &M,
) -> Result<Zeroizing<String>, OpenId4VpProtoError> {
    serialize_generated_json(message)
}

/// Deserialize an approved generated OpenID4VP message using Buffa ProtoJSON.
pub fn openid4vp_proto_from_json<M: OpenId4VpProtoJson>(
    json: &str,
) -> Result<M, OpenId4VpProtoError> {
    deserialize_generated_json(json)
}

fn deserialize_generated_json<M>(json: &str) -> Result<M, OpenId4VpProtoError>
where
    M: DeserializeOwned + Message,
{
    if json.len() > MAX_OPENID4VP_PROTO_JSON_BYTES {
        return Err(OpenId4VpProtoError::JsonDeserialize);
    }

    validate_proto_json_budget(json)?;

    let message: M =
        serde_json::from_str(json).map_err(|_| OpenId4VpProtoError::JsonDeserialize)?;
    if !generated_proto_fits_message_budget(&message) {
        return Err(OpenId4VpProtoError::JsonDeserialize);
    }
    Ok(message)
}

fn generated_proto_fits_message_budget<M: Message>(message: &M) -> bool {
    let Ok(max_bytes) = u32::try_from(MAX_OPENID4VP_PROTO_MESSAGE_BYTES) else {
        return false;
    };
    let mut cache = buffa::SizeCache::new();
    message.compute_size(&mut cache) <= max_bytes
}

#[derive(Clone, Copy)]
struct JsonBudgetSeed<'a> {
    element_count: &'a Cell<usize>,
    depth: u32,
}

impl JsonBudgetSeed<'_> {
    fn child<E: serde::de::Error>(self) -> Result<Self, E> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| E::custom("ProtoJSON nesting exceeds policy"))?;
        if depth > OPENID4VP_PROTO_RECURSION_LIMIT {
            return Err(E::custom("ProtoJSON nesting exceeds policy"));
        }
        Ok(Self {
            element_count: self.element_count,
            depth,
        })
    }

    fn charge<E: serde::de::Error>(self) -> Result<(), E> {
        let next = self
            .element_count
            .get()
            .checked_add(1)
            .ok_or_else(|| E::custom("ProtoJSON element budget exceeded"))?;
        if next > MAX_OPENID4VP_PROTO_JSON_ELEMENTS {
            return Err(E::custom("ProtoJSON element budget exceeded"));
        }
        self.element_count.set(next);
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for JsonBudgetSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonBudgetVisitor { seed: self })
    }
}

struct JsonBudgetVisitor<'a> {
    seed: JsonBudgetSeed<'a>,
}

impl<'de> Visitor<'de> for JsonBudgetVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded ProtoJSON")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<(), E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: Deserializer<'de>,
    {
        self.seed.child()?.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child = self.seed.child()?;
        while sequence.next_element_seed(child)?.is_some() {
            self.seed.charge()?;
        }
        Ok(())
    }

    fn visit_map<A>(self, mut object: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let child = self.seed.child()?;
        while object.next_key::<IgnoredAny>()?.is_some() {
            self.seed.charge()?;
            object.next_value_seed(child)?;
        }
        Ok(())
    }
}

fn validate_proto_json_budget(json: &str) -> Result<(), OpenId4VpProtoError> {
    let element_count = Cell::new(0);
    let seed = JsonBudgetSeed {
        element_count: &element_count,
        depth: 0,
    };
    let mut deserializer = serde_json::Deserializer::from_str(json);
    seed.deserialize(&mut deserializer)
        .map_err(|_| OpenId4VpProtoError::JsonDeserialize)?;
    deserializer
        .end()
        .map_err(|_| OpenId4VpProtoError::JsonDeserialize)
}

/// Encode a generated OpenID4VP protobuf message.
pub fn encode_authorization_response_proto(
    response: &pb::AuthorizationResponse,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    encode_generated_proto(response)
}

/// Decode generated OpenID4VP AuthorizationResponse protobuf bytes.
pub fn decode_authorization_response_proto(
    bytes: &[u8],
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    decode_generated_proto(bytes)
}

/// Encode generated hosted Request Object state as bounded protobuf bytes.
pub fn encode_hosted_request_object_proto(
    request_object: &pb::HostedRequestObject,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    encode_generated_proto(request_object)
}

/// Decode generated hosted Request Object state from bounded protobuf bytes.
pub fn decode_hosted_request_object_proto(
    bytes: &[u8],
) -> Result<pb::HostedRequestObject, OpenId4VpProtoError> {
    decode_generated_proto(bytes)
}

/// Encode a generated OpenID4VP AuthorizationRequest protobuf message.
pub fn encode_authorization_request_proto(
    request: &pb::AuthorizationRequest,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    encode_generated_proto(request)
}

/// Decode generated OpenID4VP AuthorizationRequest protobuf bytes.
pub fn decode_authorization_request_proto(
    bytes: &[u8],
) -> Result<pb::AuthorizationRequest, OpenId4VpProtoError> {
    decode_generated_proto(bytes)
}

/// Encode a Rust AuthorizationRequestObject as protobuf bytes.
pub fn encode_authorization_request(
    request: &AuthorizationRequestObject,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    let proto = authorization_request_to_proto(request)?;
    encode_authorization_request_proto(&proto)
}

/// Decode protobuf bytes into a Rust AuthorizationRequestObject.
pub fn decode_authorization_request(
    bytes: &[u8],
) -> Result<AuthorizationRequestObject, OpenId4VpProtoError> {
    let proto = decode_authorization_request_proto(bytes)?;
    proto_to_authorization_request(&proto)
}

/// Encode a Rust AuthorizationResponse as protobuf bytes.
pub fn encode_authorization_response(
    response: &AuthorizationResponse,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    let proto = authorization_response_to_proto(response)?;
    encode_authorization_response_proto(&proto)
}

/// Decode protobuf bytes into a Rust AuthorizationResponse.
pub fn decode_authorization_response(
    bytes: &[u8],
) -> Result<AuthorizationResponse, OpenId4VpProtoError> {
    let proto = decode_authorization_response_proto(bytes)?;
    proto_to_authorization_response(&proto)
}

/// Encode a verifier session record as bounded protobuf bytes.
///
/// Session state contains replay-sensitive nonce, state, and DCQL material.
/// Keeping persistence adapters on this schema-owned boundary avoids a second,
/// deployment-specific serialization format for those values.
pub fn encode_session_record(
    record: &SessionRecord,
) -> Result<Zeroizing<Vec<u8>>, OpenId4VpProtoError> {
    let proto = session_record_to_proto(record)?;
    encode_generated_proto(&proto)
}

/// Decode bounded protobuf bytes into validated verifier session state.
///
/// The generic decoder rejects oversized messages, excessive recursion, and
/// unknown fields before the domain mapper validates the embedded DCQL query.
pub fn decode_session_record(bytes: &[u8]) -> Result<SessionRecord, OpenId4VpProtoError> {
    let proto: pb::SessionRecord = decode_generated_proto(bytes)?;
    proto_to_session_record(&proto)
}

/// Serialize a generated AuthorizationResponse with Buffa protobuf JSON rules.
pub fn authorization_response_proto_to_json(
    response: &pb::AuthorizationResponse,
) -> Result<Zeroizing<String>, OpenId4VpProtoError> {
    openid4vp_proto_to_json(response)
}

/// Deserialize a generated AuthorizationResponse with Buffa protobuf JSON rules.
pub fn authorization_response_json_to_proto(
    json: &str,
) -> Result<pb::AuthorizationResponse, OpenId4VpProtoError> {
    openid4vp_proto_from_json(json)
}

/// Serialize a generated AuthorizationRequest with Buffa protobuf JSON rules.
pub fn authorization_request_proto_to_json(
    request: &pb::AuthorizationRequest,
) -> Result<Zeroizing<String>, OpenId4VpProtoError> {
    openid4vp_proto_to_json(request)
}

/// Deserialize a generated AuthorizationRequest with Buffa protobuf JSON rules.
pub fn authorization_request_json_to_proto(
    json: &str,
) -> Result<pb::AuthorizationRequest, OpenId4VpProtoError> {
    openid4vp_proto_from_json(json)
}
