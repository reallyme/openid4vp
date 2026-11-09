// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded OpenID4VP transport for the canonical prepared-persona protobuf.
//!
//! The format envelope carries one opaque protobuf. Its proof, issuer-status,
//! live holder-signature, and request semantics are verified by the injected
//! ZK verifier against the active OpenID4VP session, never by this parser.

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vp_types::PresentationValue;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};

/// Versioned marker for a prepared-persona `vp_token` entry.
pub const ZK_PREPARED_PERSONA_TYPE: &str = "reallyme.openid4vp.zk_prepared_persona.v1";
/// Cap the encoded prepared object before protobuf decoding or proof work.
pub const MAX_ZK_PREPARED_PERSONA_BYTES: usize = 1_048_576;
const MAX_ENCODED_BYTES: usize = 1_398_104;
const PAYLOAD_FIELD: &str = "presentation_b64u";

fn invalid() -> ZkFormatError {
    ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding)
}

/// Encode the ZK SDK's canonical prepared presentation as a JSON `vp_token`.
pub fn encode_zk_prepared_persona_value(
    presentation: &[u8],
) -> Result<PresentationValue, ZkFormatError> {
    if presentation.is_empty() || presentation.len() > MAX_ZK_PREPARED_PERSONA_BYTES {
        return Err(invalid());
    }
    let mut value = Map::new();
    value.insert(
        "type".to_owned(),
        Value::String(ZK_PREPARED_PERSONA_TYPE.to_owned()),
    );
    value.insert(
        PAYLOAD_FIELD.to_owned(),
        Value::String(bytes_to_base64url(presentation)),
    );
    Ok(PresentationValue::Json(Value::Object(value)))
}

/// Parse only the canonical two-field transport envelope when marked.
///
/// The returned bytes are still untrusted. The verifier must decode and
/// authenticate the protobuf with the independent session and status policy.
pub fn parse_zk_prepared_persona_value(
    value: &PresentationValue,
) -> Result<Option<Zeroizing<Vec<u8>>>, ZkFormatError> {
    let PresentationValue::Json(Value::Object(object)) = value else {
        return Ok(None);
    };
    if object.get("type").and_then(Value::as_str) != Some(ZK_PREPARED_PERSONA_TYPE) {
        return Ok(None);
    }
    if object.len() != 2 {
        return Err(invalid());
    }
    let encoded = object
        .get(PAYLOAD_FIELD)
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if encoded.is_empty() || encoded.len() > MAX_ENCODED_BYTES {
        return Err(invalid());
    }
    let decoded = Zeroizing::new(base64url_to_bytes(encoded).map_err(|_| invalid())?);
    if decoded.is_empty()
        || decoded.len() > MAX_ZK_PREPARED_PERSONA_BYTES
        || bytes_to_base64url(&decoded) != encoded
    {
        return Err(invalid());
    }
    Ok(Some(decoded))
}

#[cfg(test)]
#[path = "zk_prepared_persona_tests.rs"]
mod tests;
