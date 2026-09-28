// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use reallyme_openid4vp_dc_api::{
    DcApiErrorReason, JwsJsonGeneral, MAX_JWS_JSON_GENERAL_BYTES, MAX_JWS_JSON_SIGNATURES,
};
use reallyme_openid4vp_types::ClientIdentifier;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::Deserializer;
use zeroize::{Zeroize, Zeroizing};

use crate::jar::finish_verified_request_object_with_transaction_data_policy;
use crate::{
    VerifiedRequestObject, VerifiedWalletRequest, WalletError, WalletErrorReason,
    WalletInvocationContext, WalletTransactionDataPolicy,
};

/// Maximum accepted JWS JSON General Serialization input.
pub const MAX_MULTISIGNED_REQUEST_OBJECT_BYTES: usize = MAX_JWS_JSON_GENERAL_BYTES;
/// Maximum signatures accepted from one JWS JSON General Serialization input.
pub const MAX_MULTISIGNED_REQUEST_OBJECT_SIGNATURES: usize = MAX_JWS_JSON_SIGNATURES;

const MAX_COMPACT_REQUEST_OBJECT_BYTES: usize = 64 * 1024;
const MAX_PROTECTED_HEADER_BYTES: usize = 32 * 1024;

/// Verifier for one signature selected from a multi-signed Request Object.
///
/// Implementations must verify the exact compact JWS supplied to the method and
/// project `protected_client_id` into the returned request. The outer verifier
/// checks that projection before accepting the result, preventing signature
/// evidence for one client from being attached to another client's request.
pub trait MultiSignedRequestObjectSignatureVerifier: Send + Sync {
    /// Verify one signature over the shared payload.
    fn verify_multisigned_request_object_signature(
        &self,
        compact_jws: &str,
        protected_client_id: &ClientIdentifier,
        invocation: &WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError>;
}

#[cfg(feature = "jose")]
impl<R> MultiSignedRequestObjectSignatureVerifier
    for crate::verify_signed_request_object_with_jose::JoseSignedRequestObjectVerifier<R>
where
    R: crate::verify_signed_request_object_with_jose::JoseRequestObjectVerificationResolver,
{
    fn verify_multisigned_request_object_signature(
        &self,
        compact_jws: &str,
        protected_client_id: &ClientIdentifier,
        invocation: &WalletInvocationContext,
        now_unix: u64,
    ) -> Result<VerifiedRequestObject, WalletError> {
        self.verify_request_object_with_client_identifier(
            compact_jws,
            Some(protected_client_id),
            invocation,
            now_unix,
        )
    }
}

/// Verify an OpenID4VP multi-signed Request Object.
///
/// OpenID4VP 1.0 Appendix A.3.2 places `client_id` in each protected header,
/// rather than in the shared payload. Every candidate is independently bound
/// to that identifier and fully validated. The request is accepted when at
/// least one signature and its projected request are valid.
pub fn verify_multisigned_request_object(
    verifier: &impl MultiSignedRequestObjectSignatureVerifier,
    general_jws: &JwsJsonGeneral,
    invocation: &WalletInvocationContext,
    now_unix: u64,
) -> Result<VerifiedWalletRequest, WalletError> {
    verify_multisigned_request_object_with_transaction_data_policy(
        verifier,
        general_jws,
        invocation,
        now_unix,
        WalletTransactionDataPolicy::deny_all(),
    )
}

/// Verify a multi-signed Request Object with an explicit transaction-data allowlist.
pub fn verify_multisigned_request_object_with_transaction_data_policy(
    verifier: &impl MultiSignedRequestObjectSignatureVerifier,
    general_jws: &JwsJsonGeneral,
    invocation: &WalletInvocationContext,
    now_unix: u64,
    transaction_data_policy: WalletTransactionDataPolicy<'_>,
) -> Result<VerifiedWalletRequest, WalletError> {
    general_jws
        .validate()
        .map_err(|error| map_dc_api_error(error.reason()))?;

    let mut verified_but_invalid: Option<WalletError> = None;
    for signature in &general_jws.signatures {
        if !is_base64url_segment(&signature.protected)
            || !is_base64url_segment(&signature.signature)
        {
            continue;
        }
        let protected_client_id = match parse_protected_client_id(&signature.protected) {
            Ok(client_id) => client_id,
            Err(_) => continue,
        };
        let compact_jws = match build_compact_jws(
            &signature.protected,
            &general_jws.payload,
            &signature.signature,
        ) {
            Ok(compact_jws) => compact_jws,
            Err(error) => {
                verified_but_invalid = Some(error);
                continue;
            }
        };
        let verified = match verifier.verify_multisigned_request_object_signature(
            compact_jws.as_str(),
            &protected_client_id,
            invocation,
            now_unix,
        ) {
            Ok(verified) => verified,
            Err(_) => continue,
        };
        if verified.client_identifier() != Some(&protected_client_id) {
            verified_but_invalid = Some(WalletError::new(
                WalletErrorReason::TransportClientIdentifierMismatch,
            ));
            continue;
        }
        match finish_verified_request_object_with_transaction_data_policy(
            verified,
            invocation,
            now_unix,
            transaction_data_policy,
        ) {
            Ok(request) => return Ok(request),
            Err(error) => verified_but_invalid = Some(error),
        }
    }

    match verified_but_invalid {
        Some(error) => Err(error),
        None => Err(WalletError::new(
            WalletErrorReason::InvalidRequestObjectSignature,
        )),
    }
}

fn map_dc_api_error(reason: DcApiErrorReason) -> WalletError {
    let wallet_reason = match reason {
        DcApiErrorReason::RequestObjectTooLarge => WalletErrorReason::RequestObjectTooLarge,
        _ => WalletErrorReason::InvalidRequestObject,
    };
    WalletError::new(wallet_reason)
}

fn build_compact_jws(
    protected: &str,
    payload: &str,
    signature: &str,
) -> Result<Zeroizing<String>, WalletError> {
    let length = protected
        .len()
        .checked_add(payload.len())
        .and_then(|value| value.checked_add(signature.len()))
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| WalletError::new(WalletErrorReason::RequestObjectTooLarge))?;
    if length > MAX_COMPACT_REQUEST_OBJECT_BYTES {
        return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
    }
    let mut compact = Zeroizing::new(String::with_capacity(length));
    compact.push_str(protected);
    compact.push('.');
    compact.push_str(payload);
    compact.push('.');
    compact.push_str(signature);
    Ok(compact)
}

fn is_base64url_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn parse_protected_client_id(encoded_header: &str) -> Result<ClientIdentifier, WalletError> {
    if encoded_header.len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(WalletError::new(WalletErrorReason::RequestObjectTooLarge));
    }
    let header = Zeroizing::new(
        reallyme_codec::base64url::base64url_to_bytes(encoded_header)
            .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?,
    );
    let mut deserializer = serde_json::Deserializer::from_slice(header.as_slice());
    let client_id = deserializer
        .deserialize_map(ProtectedHeaderVisitor)
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    deserializer
        .end()
        .map_err(|_| WalletError::new(WalletErrorReason::InvalidRequestObject))?;
    client_id.ok_or_else(|| WalletError::new(WalletErrorReason::InvalidClientIdentifierPrefix))
}

struct ProtectedHeaderVisitor;

impl<'de> Visitor<'de> for ProtectedHeaderVisitor {
    type Value = Option<ClientIdentifier>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a protected JWS header with one client_id")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut client_id = None;
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(
                    "duplicate protected header member",
                ));
            }
            if key == "client_id" {
                let mut value = map.next_value::<String>()?;
                let parsed = ClientIdentifier::parse(&value)
                    .map_err(|_| serde::de::Error::custom("invalid protected client_id"));
                value.zeroize();
                client_id = Some(parsed?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(client_id)
    }
}

#[cfg(test)]
#[path = "multisigned_request_object_tests.rs"]
mod tests;
