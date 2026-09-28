// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::VpToken;

use crate::sensitive_json::{decode_bounded_json, MAX_PRESENTATION_JSON_BYTES};
use crate::OpenId4VpProtoError;

/// Decode the spec-native Direct Post `vp_token` JSON object.
///
/// The outer Authorization Response remains transport-owned; only the
/// explicitly JSON-native presentation object crosses this JSON choke point.
pub fn decode_vp_token_json(bytes: &[u8]) -> Result<VpToken, OpenId4VpProtoError> {
    let vp_token: VpToken = decode_bounded_json(bytes, MAX_PRESENTATION_JSON_BYTES)?;
    if vp_token.is_empty() || vp_token.values().any(Vec::is_empty) {
        return Err(OpenId4VpProtoError::InvalidField);
    }
    Ok(vp_token)
}
