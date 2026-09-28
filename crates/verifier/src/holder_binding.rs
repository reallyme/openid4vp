// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;

use crate::compare_secret::constant_time_str_eq;
use crate::validate_transaction_data_binding::validate_transaction_data_binding;
use crate::{RequestBinding, VerifierError, VerifierErrorReason};

const SHA256_DIGEST_BYTES: usize = 32;

/// Decoded holder-binding JWT claims relevant to OpenID4VP binding.
///
/// Signature verification and format-specific JWT parsing live in
/// `reallyme/ssi` envelope crates and thin format adapters. This pure
/// validator ports the meproto claim checks that remain valid after the
/// final-spec DCQL rewrite.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderBindingClaims {
    /// Audience values from the holder-binding proof.
    #[serde(deserialize_with = "deserialize_audience")]
    pub audience: Vec<String>,
    /// Nonce from the holder-binding proof.
    pub nonce: String,
    /// Optional expiration time in Unix seconds.
    ///
    /// Standard SD-JWT KB-JWT holder binding requires `nonce` and `aud`.
    /// Formats that also supply `exp` get full temporal enforcement; absent
    /// `exp` is represented as `0` to keep the FFI/proto shape stable.
    pub expiration_unix: u64,
    /// Optional issued-at time in Unix seconds.
    #[serde(default)]
    pub issued_at_unix: u64,
    /// Optional SD-JWT KB-JWT `sd_hash` claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sd_hash: Option<String>,
    /// Transaction-data digests extracted after holder-proof verification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_data_hashes: Vec<[u8; SHA256_DIGEST_BYTES]>,
    /// Explicit digest algorithm when the holder proof supplied it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_data_hashes_alg: Option<TransactionDataHashAlgorithm>,
}

impl fmt::Debug for HolderBindingClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderBindingClaims")
            .field("audience_count", &self.audience.len())
            .field("expiration_unix", &self.expiration_unix)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("has_sd_hash", &self.sd_hash.is_some())
            .field(
                "transaction_data_hash_count",
                &self.transaction_data_hashes.len(),
            )
            .field(
                "transaction_data_hashes_alg",
                &self.transaction_data_hashes_alg,
            )
            .field("claim_values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for HolderBindingClaims {
    fn zeroize(&mut self) {
        self.audience.zeroize();
        self.nonce.zeroize();
        self.expiration_unix.zeroize();
        self.issued_at_unix.zeroize();
        self.sd_hash.zeroize();
        self.transaction_data_hashes.zeroize();
        self.transaction_data_hashes_alg = None;
    }
}

impl Drop for HolderBindingClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for HolderBindingClaims {}

/// Validate decoded holder-binding claims against a verifier request binding.
pub fn validate_holder_binding_claims(
    binding: &RequestBinding,
    claims: &HolderBindingClaims,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if !binding.transaction_data_bindings.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    validate_holder_binding_claims_for_query(binding, None, claims, now_unix)
}

pub(crate) fn validate_holder_binding_claims_for_query(
    binding: &RequestBinding,
    query_id: Option<&QueryId>,
    claims: &HolderBindingClaims,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if claims.audience.is_empty() || claims.nonce.is_empty() {
        return Err(VerifierError::new(
            VerifierErrorReason::MissingHolderBindingClaim,
        ));
    }

    let expected_audience = expected_holder_binding_audience(binding);
    if !claims
        .audience
        .iter()
        .any(|audience| audience == &expected_audience)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingAudienceMismatch,
        ));
    }

    if !constant_time_str_eq(&claims.nonce, &binding.nonce) {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingNonceMismatch,
        ));
    }

    if claims.expiration_unix != 0
        && (claims.expiration_unix <= now_unix || claims.expiration_unix > binding.expiry_unix)
    {
        return Err(VerifierError::new(
            VerifierErrorReason::HolderBindingExpired,
        ));
    }

    match query_id {
        Some(query_id) => validate_transaction_data_binding(binding, query_id, claims)?,
        None if claims.transaction_data_hashes.is_empty()
            && claims.transaction_data_hashes_alg.is_none() => {}
        None => return Err(VerifierError::new(VerifierErrorReason::InvalidBinding)),
    }

    Ok(())
}

/// Resolve the one audience value used by both format-level JWT verification
/// and protocol-level holder-binding validation.
///
/// Digital Credentials API holder proofs are bound to the invoking browser
/// origin, including when the Authorization Request itself was signed. Keeping
/// the transport identity on the session prevents a signed request from
/// accidentally falling back to its Client Identifier as the proof audience.
pub(crate) fn expected_holder_binding_audience(binding: &RequestBinding) -> String {
    binding.dc_api_origin.as_ref().map_or_else(
        || binding.client_id.to_wire_value(),
        |origin| ["origin:", origin.as_str()].concat(),
    )
}

fn deserialize_audience<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }

    match Audience::deserialize(deserializer)? {
        Audience::One(value) => Ok(vec![value]),
        Audience::Many(values) => Ok(values),
    }
}

#[cfg(test)]
#[path = "holder_binding_tests.rs"]
mod tests;
