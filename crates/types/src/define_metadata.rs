// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

use reallyme_openid4vp_dcql::{CredentialFormat, DcqlQuery};

use crate::zeroize_json::zeroize_json_value;
use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

const MAX_VP_FORMATS_SUPPORTED: usize = 32;
const MAX_ALGORITHMS_PER_FORMAT_MEMBER: usize = 32;
const MAX_ALGORITHM_IDENTIFIER_BYTES: usize = 128;

/// Raw verifier metadata carried inline or resolved by client identifier rules.
///
/// OpenID4VP 1.0 defines `vp_formats_supported` as an object whose values are
/// format-specific parameter objects. Keeping the extension-friendly protocol
/// object intact avoids publishing a lossy DTO that silently changes those
/// shapes or invents non-standard capability members.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientMetadata {
    /// Exact metadata JSON object.
    pub raw: JsonValue,
}

impl ClientMetadata {
    /// Validate format capabilities and bind every DCQL Credential Query to a
    /// format advertised by the verifier.
    ///
    /// Unknown formats and members remain forward-compatible, but every
    /// format value must be an object. Known final-spec algorithm members are
    /// bounded and type-checked so malformed metadata cannot silently weaken
    /// the selection policy.
    pub fn validate_for_dcql(&self, query: &DcqlQuery) -> Result<(), OpenId4vpTypeError> {
        let metadata = self.raw.as_object().ok_or_else(unsupported_metadata)?;
        let formats = metadata
            .get("vp_formats_supported")
            .and_then(JsonValue::as_object)
            .ok_or_else(unsupported_metadata)?;
        if formats.is_empty() || formats.len() > MAX_VP_FORMATS_SUPPORTED {
            return Err(unsupported_metadata());
        }

        for (format, capabilities) in formats {
            validate_format_capabilities(format, capabilities)?;
        }
        for credential in &query.credentials {
            if !formats.contains_key(credential.format.as_str()) {
                return Err(unsupported_metadata());
            }
        }
        Ok(())
    }
}

fn validate_format_capabilities(
    format: &str,
    capabilities: &JsonValue,
) -> Result<(), OpenId4vpTypeError> {
    let capabilities = capabilities.as_object().ok_or_else(unsupported_metadata)?;
    match format {
        CredentialFormat::DC_SD_JWT => {
            validate_optional_string_array(capabilities, "sd-jwt_alg_values")?;
            validate_optional_string_array(capabilities, "kb-jwt_alg_values")?;
        }
        CredentialFormat::MSO_MDOC => {
            validate_optional_integer_array(capabilities, "issuerauth_alg_values")?;
            validate_optional_integer_array(capabilities, "deviceauth_alg_values")?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_optional_string_array(
    capabilities: &JsonMap<String, JsonValue>,
    member: &str,
) -> Result<(), OpenId4vpTypeError> {
    let Some(values) = capabilities.get(member) else {
        return Ok(());
    };
    let values = values.as_array().ok_or_else(unsupported_metadata)?;
    if values.is_empty() || values.len() > MAX_ALGORITHMS_PER_FORMAT_MEMBER {
        return Err(unsupported_metadata());
    }
    if values.iter().any(|value| {
        value.as_str().is_none_or(|algorithm| {
            algorithm.is_empty()
                || algorithm.len() > MAX_ALGORITHM_IDENTIFIER_BYTES
                || algorithm.chars().any(char::is_control)
        })
    }) {
        return Err(unsupported_metadata());
    }
    Ok(())
}

fn validate_optional_integer_array(
    capabilities: &JsonMap<String, JsonValue>,
    member: &str,
) -> Result<(), OpenId4vpTypeError> {
    let Some(values) = capabilities.get(member) else {
        return Ok(());
    };
    let values = values.as_array().ok_or_else(unsupported_metadata)?;
    if values.is_empty() || values.len() > MAX_ALGORITHMS_PER_FORMAT_MEMBER {
        return Err(unsupported_metadata());
    }
    if values.iter().any(|value| {
        value
            .as_i64()
            .and_then(|algorithm| i32::try_from(algorithm).ok())
            .is_none()
    }) {
        return Err(unsupported_metadata());
    }
    Ok(())
}

const fn unsupported_metadata() -> OpenId4vpTypeError {
    OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::UnsupportedMetadataCapability)
}

impl fmt::Debug for ClientMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientMetadata(<redacted>)")
    }
}

impl Zeroize for ClientMetadata {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.raw);
    }
}

impl Drop for ClientMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClientMetadata {}

#[cfg(test)]
#[path = "define_metadata_tests.rs"]
mod tests;
