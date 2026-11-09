// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared OpenID4VP projection into the prepared holder-authentication request.
//!
//! The wallet derives these fields from its verified Authorization Request;
//! the verifier derives them from its retained, one-time session. A response
//! cannot nominate its own request or relax its requested claim policy.

use reallyme_openid4vp_dcql::CredentialQuery;
use reallyme_openid4vp_types::ResponseMode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};
use crate::zeroize_json::zeroize_json_value;

const MAX_QUERY_CANONICAL_BYTES: usize = 65_536;
const MAX_CONTEXT_FIELD_BYTES: usize = 4_096;
const MAX_TRANSACTION_HASHES: usize = 64;
const MAX_NONCE_BYTES: usize = 1_024;
const MAX_AUDIENCE_BYTES: usize = 4_096;
const CLAIMS_DOMAIN: &[u8] = b"RMPVP-CLAIMS1";
const POLICY_DOMAIN: &[u8] = b"RMPVP-POLICY1";
const TRANSACTION_DOMAIN: &[u8] = b"RMPVP-TX1";
const TRANSPORT_DOMAIN: &[u8] = b"RMPVP-TRANSPORT1";

/// The authenticated OpenID4VP values that both sides retain for one query.
/// The `issued_at_unix` and `expires_at_unix` values must come from the same
/// request; prepared profiles require both even for unsigned DC API requests.
pub struct PreparedOpenId4VpRequestInput<'a> {
    /// Exact request nonce.
    pub nonce: &'a str,
    /// Verified Client Identifier or authenticated browser origin audience.
    pub audience: &'a str,
    /// One DCQL credential query selected by the response key.
    pub query: &'a CredentialQuery,
    /// Ordered, query-scoped transaction-data SHA-256 digests.
    pub transaction_hashes: &'a [[u8; 32]],
    /// Negotiated OpenID4VP response mode.
    pub response_mode: ResponseMode,
    /// Verified response destination, if this mode has one.
    pub response_uri: Option<&'a str>,
    /// Verified redirect destination, if this mode has one.
    pub redirect_uri: Option<&'a str>,
    /// Verifier state retained with the request.
    pub state: Option<&'a str>,
    /// Authenticated issuance time.
    pub issued_at_unix: u64,
    /// Authenticated exclusive expiry.
    pub expires_at_unix: u64,
}

/// Digests inserted into the ZK protobuf `ZkPreparedVerifierRequestV1`.
pub struct PreparedOpenId4VpRequestHashes {
    /// SHA-256 of the exact OpenID4VP nonce string.
    pub nonce: [u8; 32],
    /// SHA-256 of the authenticated verifier audience.
    pub audience_sha256: [u8; 32],
    /// Domain-separated ordered transaction-data transcript.
    pub transaction_data_sha256: [u8; 32],
    /// Domain-separated canonical DCQL credential query.
    pub requested_claims_sha256: [u8; 32],
    /// Domain-separated canonical DCQL policy metadata.
    pub verifier_policy_sha256: [u8; 32],
    /// Domain-separated response mode, destinations, and state.
    pub transport_context_sha256: [u8; 32],
}

impl Drop for PreparedOpenId4VpRequestHashes {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.audience_sha256.zeroize();
        self.transaction_data_sha256.zeroize();
        self.requested_claims_sha256.zeroize();
        self.verifier_policy_sha256.zeroize();
        self.transport_context_sha256.zeroize();
    }
}

fn invalid() -> ZkFormatError {
    ZkFormatError::new(ZkFormatErrorReason::BindingMismatch)
}

fn hash_tagged(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    digest.finalize().into()
}

fn canonical_hash(domain: &[u8], value: &mut Value) -> Result<[u8; 32], ZkFormatError> {
    let canonical =
        reallyme_codec::jcs::canonicalize_trusted_json_value(value).map_err(|_| invalid());
    zeroize_json_value(value);
    let canonical = Zeroizing::new(canonical?);
    if canonical.len() > MAX_QUERY_CANONICAL_BYTES {
        return Err(invalid());
    }
    Ok(hash_tagged(domain, canonical.as_bytes()))
}

fn append_text(target: &mut Zeroizing<Vec<u8>>, value: Option<&str>) -> Result<(), ZkFormatError> {
    match value {
        Some(value) if value.len() <= MAX_CONTEXT_FIELD_BYTES => {
            let length = u32::try_from(value.len()).map_err(|_| invalid())?;
            let extra = value.len().checked_add(4).ok_or_else(invalid)?;
            target.try_reserve_exact(extra).map_err(|_| invalid())?;
            target.extend_from_slice(&length.to_be_bytes());
            target.extend_from_slice(value.as_bytes());
        }
        None => {
            target.try_reserve_exact(4).map_err(|_| invalid())?;
            target.extend_from_slice(&u32::MAX.to_be_bytes());
        }
        Some(_) => return Err(invalid()),
    }
    Ok(())
}

/// Derive the six ZK request inputs from one independently authenticated
/// OpenID4VP request/session projection. This helper is shared by wallet and
/// verifier adapters so their byte-level signature transcript cannot drift.
pub fn derive_prepared_openid4vp_request_hashes(
    input: PreparedOpenId4VpRequestInput<'_>,
) -> Result<PreparedOpenId4VpRequestHashes, ZkFormatError> {
    if input.nonce.is_empty()
        || input.nonce.len() > MAX_NONCE_BYTES
        || input.audience.is_empty()
        || input.audience.len() > MAX_AUDIENCE_BYTES
        || input.issued_at_unix >= input.expires_at_unix
        || input.transaction_hashes.len() > MAX_TRANSACTION_HASHES
    {
        return Err(invalid());
    }
    let endpoints_match_mode = match input.response_mode {
        ResponseMode::Fragment | ResponseMode::FormPost => {
            input.redirect_uri.is_some() && input.response_uri.is_none()
        }
        ResponseMode::DirectPost | ResponseMode::DirectPostJwt => {
            input.response_uri.is_some() && input.redirect_uri.is_none()
        }
        ResponseMode::DcApi | ResponseMode::DcApiJwt => {
            input.response_uri.is_none() && input.redirect_uri.is_none()
        }
    };
    if !endpoints_match_mode {
        return Err(invalid());
    }
    let mut query_json = serde_json::to_value(input.query).map_err(|_| invalid())?;
    let requested_claims_sha256 = canonical_hash(CLAIMS_DOMAIN, &mut query_json)?;
    let verifier_policy_sha256 =
        canonical_hash(POLICY_DOMAIN, &mut Value::Object(input.query.meta.clone()))?;

    let transaction_count = u16::try_from(input.transaction_hashes.len()).map_err(|_| invalid())?;
    let mut transaction = Zeroizing::new(Vec::new());
    let transaction_bytes = input
        .transaction_hashes
        .len()
        .checked_mul(32)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(invalid)?;
    transaction
        .try_reserve_exact(transaction_bytes)
        .map_err(|_| invalid())?;
    transaction.extend_from_slice(&transaction_count.to_be_bytes());
    for digest in input.transaction_hashes {
        transaction.extend_from_slice(digest);
    }
    let transaction_data_sha256 = hash_tagged(TRANSACTION_DOMAIN, &transaction);

    let mode = match input.response_mode {
        ResponseMode::Fragment => 1_u8,
        ResponseMode::FormPost => 2,
        ResponseMode::DirectPost => 3,
        ResponseMode::DirectPostJwt => 4,
        ResponseMode::DcApi => 5,
        ResponseMode::DcApiJwt => 6,
    };
    let mut transport = Zeroizing::new(Vec::new());
    transport.try_reserve_exact(1).map_err(|_| invalid())?;
    transport.push(mode);
    append_text(&mut transport, input.response_uri)?;
    append_text(&mut transport, input.redirect_uri)?;
    append_text(&mut transport, input.state)?;

    Ok(PreparedOpenId4VpRequestHashes {
        nonce: Sha256::digest(input.nonce.as_bytes()).into(),
        audience_sha256: Sha256::digest(input.audience.as_bytes()).into(),
        transaction_data_sha256,
        requested_claims_sha256,
        verifier_policy_sha256,
        transport_context_sha256: hash_tagged(TRANSPORT_DOMAIN, &transport),
    })
}

#[cfg(test)]
#[path = "zk_prepared_request_tests.rs"]
mod tests;
