// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use reallyme_openid4vp_dcql::DcqlQuery;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ClientIdentifier, ClientMetadata, OpenId4vpTypeError, OpenId4vpTypeErrorReason, TransactionData,
};

/// Maximum number of attestations admitted in one request.
pub const MAX_VERIFIER_INFO_ENTRIES: usize = 16;
/// Maximum conservative encoded JSON size admitted for one attestation payload.
pub const MAX_VERIFIER_INFO_DATA_BYTES: usize = 256 * 1_024;
const MAX_VERIFIER_INFO_FORMAT_BYTES: usize = 256;
const MAX_VERIFIER_INFO_CREDENTIAL_IDS: usize = 32;
const MAX_VERIFIER_INFO_CREDENTIAL_ID_BYTES: usize = 128;
const MAX_VERIFIER_INFO_JSON_DEPTH: usize = 64;
const MAX_VERIFIER_INFO_JSON_NODES: usize = 4_096;
const MAX_JSON_NUMBER_BYTES: usize = 64;

/// Profile-defined attestation carried inside the signed `verifier_info` array.
///
/// Request signature verification authenticates transport of this value, but
/// does not establish the attestation issuer's trust or its authorization.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierInfoEntry {
    format: String,
    data: JsonValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_ids: Option<Vec<String>>,
}

impl VerifierInfoEntry {
    /// Construct a bounded attestation container without asserting its trust.
    pub fn try_new(
        format: String,
        data: JsonValue,
        credential_ids: Option<Vec<String>>,
    ) -> Result<Self, OpenId4vpTypeError> {
        let value = Self {
            format,
            data,
            credential_ids,
        };
        value.validate()?;
        Ok(value)
    }

    /// Reject malformed or resource-exhausting generic attestation shapes.
    pub fn validate(&self) -> Result<(), OpenId4vpTypeError> {
        if self.format.is_empty() || self.format.len() > MAX_VERIFIER_INFO_FORMAT_BYTES {
            return Err(verifier_info_error());
        }
        if !matches!(&self.data, JsonValue::Object(_) | JsonValue::String(_)) {
            return Err(verifier_info_error());
        }
        if matches!(&self.data, JsonValue::String(value) if value.is_empty())
            || matches!(&self.data, JsonValue::Object(value) if value.is_empty())
        {
            return Err(verifier_info_error());
        }
        validate_verifier_info_json_size(&self.data)?;
        if let Some(ids) = &self.credential_ids {
            if ids.is_empty() || ids.len() > MAX_VERIFIER_INFO_CREDENTIAL_IDS {
                return Err(verifier_info_error());
            }
            let mut unique = std::collections::BTreeSet::new();
            for id in ids {
                if id.is_empty()
                    || id.len() > MAX_VERIFIER_INFO_CREDENTIAL_ID_BYTES
                    || !unique.insert(id)
                {
                    return Err(verifier_info_error());
                }
            }
        }
        Ok(())
    }
    /// Attestation format identifier; interpretation belongs to its profile.
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }

    /// Untrusted attestation payload until the profile validates its proof.
    #[must_use]
    pub const fn data(&self) -> &JsonValue {
        &self.data
    }

    /// DCQL query identifiers to which this attestation applies, if narrowed.
    #[must_use]
    pub fn credential_ids(&self) -> Option<&[String]> {
        self.credential_ids.as_deref()
    }
}

impl fmt::Debug for VerifierInfoEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifierInfoEntry(<redacted>)")
    }
}

impl Zeroize for VerifierInfoEntry {
    fn zeroize(&mut self) {
        self.format.zeroize();
        crate::zeroize_json::zeroize_json_value(&mut self.data);
        self.credential_ids.zeroize();
    }
}

impl Drop for VerifierInfoEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifierInfoEntry {}

const fn verifier_info_error() -> OpenId4vpTypeError {
    OpenId4vpTypeError::new(OpenId4vpTypeErrorReason::InvalidVerifierInfo)
}

fn validate_verifier_info_json_size(value: &JsonValue) -> Result<(), OpenId4vpTypeError> {
    // Count the JSON representation without serializing sensitive attestation
    // content into a second allocation. Numeric values use a conservative
    // bound; a boundary serializer applies its own exact byte limit.
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    let mut bytes = 0_usize;
    while let Some((node, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or_else(verifier_info_error)?;
        if nodes > MAX_VERIFIER_INFO_JSON_NODES || depth > MAX_VERIFIER_INFO_JSON_DEPTH {
            return Err(verifier_info_error());
        }
        let structural_bytes = match node {
            JsonValue::Null => 4,
            JsonValue::Bool(_) => 5,
            JsonValue::Number(_) => MAX_JSON_NUMBER_BYTES,
            JsonValue::String(text) => escaped_json_len(text)?
                .checked_add(2)
                .ok_or_else(verifier_info_error)?,
            JsonValue::Array(items) => {
                if nodes
                    .checked_add(stack.len())
                    .and_then(|count| count.checked_add(items.len()))
                    .is_none_or(|count| count > MAX_VERIFIER_INFO_JSON_NODES)
                {
                    return Err(verifier_info_error());
                }
                let child_depth = depth.checked_add(1).ok_or_else(verifier_info_error)?;
                stack.extend(items.iter().map(|item| (item, child_depth)));
                let separators = if items.is_empty() {
                    0
                } else {
                    items.len().checked_sub(1).ok_or_else(verifier_info_error)?
                };
                2_usize
                    .checked_add(separators)
                    .ok_or_else(verifier_info_error)?
            }
            JsonValue::Object(members) => {
                if nodes
                    .checked_add(stack.len())
                    .and_then(|count| count.checked_add(members.len()))
                    .is_none_or(|count| count > MAX_VERIFIER_INFO_JSON_NODES)
                {
                    return Err(verifier_info_error());
                }
                let child_depth = depth.checked_add(1).ok_or_else(verifier_info_error)?;
                for (key, member) in members {
                    let key_bytes = escaped_json_len(key)?
                        .checked_add(3)
                        .ok_or_else(verifier_info_error)?;
                    bytes = bytes
                        .checked_add(key_bytes)
                        .ok_or_else(verifier_info_error)?;
                    stack.push((member, child_depth));
                }
                let separators = if members.is_empty() {
                    0
                } else {
                    members
                        .len()
                        .checked_sub(1)
                        .ok_or_else(verifier_info_error)?
                };
                2_usize
                    .checked_add(separators)
                    .ok_or_else(verifier_info_error)?
            }
        };
        bytes = bytes
            .checked_add(structural_bytes)
            .ok_or_else(verifier_info_error)?;
        if bytes > MAX_VERIFIER_INFO_DATA_BYTES {
            return Err(verifier_info_error());
        }
    }
    Ok(())
}

fn escaped_json_len(text: &str) -> Result<usize, OpenId4vpTypeError> {
    let mut len = 0_usize;
    for character in text.chars() {
        let encoded = match character {
            '\u{0000}'..='\u{001f}' => 6,
            '"' | '\\' => 2,
            _ => character.len_utf8(),
        };
        len = len.checked_add(encoded).ok_or_else(verifier_info_error)?;
    }
    Ok(len)
}

/// Request Object retrieval method for `request_uri`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestUriMethod {
    /// Retrieve the Request Object with HTTP GET.
    #[serde(rename = "get")]
    Get,
    /// Retrieve the Request Object with HTTP POST.
    #[serde(rename = "post")]
    Post,
}

/// OpenID4VP response type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    /// `vp_token`.
    #[serde(rename = "vp_token")]
    VpToken,
}

/// OpenID4VP response mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseMode {
    /// OAuth fragment response.
    #[serde(rename = "fragment")]
    Fragment,
    /// OAuth form post response.
    #[serde(rename = "form_post")]
    FormPost,
    /// OpenID4VP direct POST response.
    #[serde(rename = "direct_post")]
    DirectPost,
    /// OpenID4VP encrypted direct POST response.
    #[serde(rename = "direct_post.jwt")]
    DirectPostJwt,
    /// Digital Credentials API response.
    #[serde(rename = "dc_api")]
    DcApi,
    /// Digital Credentials API encrypted response.
    #[serde(rename = "dc_api.jwt")]
    DcApiJwt,
}

/// OpenID4VP Authorization Request Object.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationRequestObject {
    /// Full final-spec Client Identifier including any prefix.
    ///
    /// Signed requests require this value. Unsigned Digital Credentials API
    /// requests omit it and rely on browser-origin binding instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<ClientIdentifier>,
    /// OAuth response type.
    pub response_type: ResponseType,
    /// OAuth/OpenID4VP response mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,
    /// Verifier response endpoint for `direct_post` and `direct_post.jwt`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_uri: Option<String>,
    /// Redirect URI for front-channel responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Request nonce used for holder binding and replay prevention.
    pub nonce: String,
    /// Wallet nonce echoed by POST `request_uri` responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_nonce: Option<String>,
    /// OIDC state value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Final-spec DCQL query.
    pub dcql_query: DcqlQuery,
    /// Native transaction data request field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data: Option<Vec<TransactionData>>,
    /// Verifier metadata carried inline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,
    /// Unsupported metadata-by-reference extension supplied by some ecosystems.
    ///
    /// OpenID4VP 1.0 final does not define `client_metadata_uri`. Wallet-side
    /// validation rejects this field unless the host injects fresh, trusted
    /// metadata evidence for the exact URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_metadata_uri: Option<String>,
    /// Attestations supplied by the verifier and covered by the request proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_info: Option<Vec<VerifierInfoEntry>>,
    /// Origins authorized to invoke a signed Digital Credentials API request.
    ///
    /// OpenID4VP final treats `expected_origins` as required for signed
    /// Digital Credentials API requests. Transport adapters populate and
    /// enforce this with browser origin data; unsigned DC API requests omit
    /// `client_id` and do not use this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_origins: Option<Vec<String>>,
    /// Request Object issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Request Object audience.
    #[serde(
        default,
        deserialize_with = "deserialize_optional_audience",
        skip_serializing_if = "Option::is_none"
    )]
    pub aud: Option<Vec<String>>,
    /// Issued-at time in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Expiration time in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
}

impl fmt::Debug for AuthorizationRequestObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestObject")
            .field("has_client_id", &self.client_id.is_some())
            .field("response_type", &self.response_type)
            .field("response_mode", &self.response_mode)
            .field("has_response_uri", &self.response_uri.is_some())
            .field("has_redirect_uri", &self.redirect_uri.is_some())
            .field(
                "transaction_data_count",
                &self.transaction_data.as_ref().map(Vec::len),
            )
            .field("has_client_metadata", &self.client_metadata.is_some())
            .field(
                "verifier_info_count",
                &self.verifier_info.as_ref().map(Vec::len),
            )
            .field(
                "expected_origin_count",
                &self.expected_origins.as_ref().map(Vec::len),
            )
            .field("request_values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for AuthorizationRequestObject {
    fn zeroize(&mut self) {
        self.client_id.zeroize();
        self.response_uri.zeroize();
        self.redirect_uri.zeroize();
        self.nonce.zeroize();
        self.wallet_nonce.zeroize();
        self.state.zeroize();
        self.dcql_query.zeroize();
        self.transaction_data.zeroize();
        self.client_metadata.zeroize();
        self.client_metadata_uri.zeroize();
        self.verifier_info.zeroize();
        self.expected_origins.zeroize();
        self.iss.zeroize();
        self.aud.zeroize();
        self.iat.zeroize();
        self.exp.zeroize();
    }
}

impl Drop for AuthorizationRequestObject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestObject {}

fn deserialize_optional_audience<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    match Option::<Audience>::deserialize(deserializer)? {
        Some(Audience::One(value)) => Ok(Some(vec![value])),
        Some(Audience::Many(values)) => Ok(Some(values)),
        None => Ok(None),
    }
}

#[cfg(test)]
#[path = "request_tests.rs"]
mod tests;
