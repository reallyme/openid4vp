// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Authenticated OpenID4VP request projection for prepared persona proofs.
//!
//! Proof construction and private-token reservation belong to the injected ZK
//! provider. The wallet passes it only digests derived from a verified request.

use reallyme_codec::base64url::{base64url_to_bytes, bytes_to_base64url};
use reallyme_openid4vp_dcql::{CredentialFormat, QueryId};
use reallyme_openid4vp_formats::{
    derive_prepared_openid4vp_request_hashes, encode_zk_prepared_persona_value,
    PreparedOpenId4VpRequestHashes, PreparedOpenId4VpRequestInput,
};
use reallyme_openid4vp_types::{PresentationValue, ResponseMode, TransactionDataHash};
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm, persona_evidence::ZkPersonaCredentialEvidenceMode,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::prepare_zk_presentation::expected_audience;
use crate::{
    VerifiedUnsignedDcApiRequest, WalletAuthorizationRequest, WalletError, WalletErrorReason,
    WalletInvocationContext,
};

const MAX_CLAIM_VALUE_BYTES: usize = 64;
const MAX_TRANSACTION_HASHES: usize = 64;

fn invalid() -> WalletError {
    WalletError::new(WalletErrorReason::ZkDerivationFailed)
}

/// One selected claim and the exact live transcript to be signed by the
/// prepared public persona or the reserved one-time private token key.
pub struct WalletPreparedPersonaRequest {
    mode: ZkPersonaCredentialEvidenceMode,
    hash_strategy: ZkCredentialHashAlgorithm,
    claim_name_hash: [u8; 32],
    claim_value: Zeroizing<Vec<u8>>,
    hashes: PreparedOpenId4VpRequestHashes,
    response_mode: ResponseMode,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

impl Drop for WalletPreparedPersonaRequest {
    fn drop(&mut self) {
        self.claim_name_hash.zeroize();
    }
}

impl ZeroizeOnDrop for WalletPreparedPersonaRequest {}

impl WalletPreparedPersonaRequest {
    /// Circuit profile demanded by the verified query.
    #[must_use]
    pub const fn mode(&self) -> ZkPersonaCredentialEvidenceMode {
        self.mode
    }

    /// Circuit hash lane demanded by the verified query.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.hash_strategy
    }

    /// Exact claim name selected by the verifier.
    #[must_use]
    pub const fn claim_name_hash(&self) -> &[u8; 32] {
        &self.claim_name_hash
    }

    /// Exact selected public claim value.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        &self.claim_value
    }

    /// Request digests shared with the verifier's retained-session projection.
    #[must_use]
    pub const fn hashes(&self) -> &PreparedOpenId4VpRequestHashes {
        &self.hashes
    }

    /// Response mode authenticated by the live holder signature.
    #[must_use]
    pub const fn response_mode(&self) -> ResponseMode {
        self.response_mode
    }

    /// Inclusive request issuance time.
    #[must_use]
    pub const fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    /// Exclusive request expiry time.
    #[must_use]
    pub const fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

/// Project a signed or browser-authenticated OpenID4VP request into the exact
/// prepared-persona claim and live-authentication inputs.
pub fn prepare_zk_prepared_persona_request(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
) -> Result<WalletPreparedPersonaRequest, WalletError> {
    let request = verified_request.request();
    let issued_at_unix = request.iat.ok_or_else(invalid)?;
    let expires_at_unix = request.exp.ok_or_else(invalid)?;
    prepare_zk_prepared_persona_request_at(
        verified_request,
        invocation,
        query_id,
        issued_at_unix,
        expires_at_unix,
    )
}

/// Project a browser-authenticated unsigned DC API request into the prepared
/// transcript. Its time hint is untrusted; the verifier must match it to its
/// independently retained request session before accepting the presentation.
pub fn prepare_zk_prepared_persona_unsigned_dc_api_request(
    verified_request: &VerifiedUnsignedDcApiRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
) -> Result<WalletPreparedPersonaRequest, WalletError> {
    let hint = verified_request.untrusted_time_hint().ok_or_else(invalid)?;
    prepare_zk_prepared_persona_request_at(
        verified_request,
        invocation,
        query_id,
        hint.issued_at_unix(),
        hint.expires_at_unix(),
    )
}

fn prepare_zk_prepared_persona_request_at(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<WalletPreparedPersonaRequest, WalletError> {
    let request = verified_request.request();
    let query = request
        .dcql_query
        .credentials
        .iter()
        .find(|candidate| candidate.id == *query_id)
        .ok_or_else(|| WalletError::new(WalletErrorReason::UnknownSelectedCredentialQuery))?;
    if query.format.as_str() != CredentialFormat::REALLYME_ZK_V1
        || !query.require_cryptographic_holder_binding
        || query.claims.is_some()
        || query.claim_sets.is_some()
        || query.trusted_authorities.is_some()
        || query.meta.len() != 4
    {
        return Err(invalid());
    }
    let profile = query
        .meta
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .and_then(ZkPersonaCredentialEvidenceMode::from_identifier)
        .ok_or_else(invalid)?;
    let hash_strategy = match query
        .meta
        .get("hash_strategy")
        .and_then(serde_json::Value::as_str)
    {
        Some("sha256") => ZkCredentialHashAlgorithm::Sha256,
        Some("poseidon2") => ZkCredentialHashAlgorithm::Poseidon2,
        _ => return Err(invalid()),
    };
    let encoded_name = query
        .meta
        .get("claim_name_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    let claim_name_hash =
        super::prepare_zk_presentation::helpers::parse_lower_hex_hash(encoded_name)
            .ok_or_else(invalid)?;
    let encoded_value = query
        .meta
        .get("claim_value_b64u")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid)?;
    if encoded_value.is_empty() || encoded_value.len() > 86 {
        return Err(invalid());
    }
    let claim_value = Zeroizing::new(base64url_to_bytes(encoded_value).map_err(|_| invalid())?);
    if claim_value.is_empty()
        || claim_value.len() > MAX_CLAIM_VALUE_BYTES
        || bytes_to_base64url(&claim_value) != encoded_value
    {
        return Err(invalid());
    }
    let response_mode = request.response_mode.ok_or_else(invalid)?;
    let audience = expected_audience(request, invocation)?;
    let mut transaction_hashes = Vec::new();
    for data in request.transaction_data.as_deref().unwrap_or_default() {
        if data
            .credential_ids()
            .iter()
            .any(|id| id == query_id.as_str())
        {
            if transaction_hashes.len() >= MAX_TRANSACTION_HASHES {
                return Err(invalid());
            }
            transaction_hashes
                .try_reserve_exact(1)
                .map_err(|_| invalid())?;
            transaction_hashes.push(
                TransactionDataHash::sha256_transaction_data(data)
                    .map_err(|_| invalid())?
                    .digest,
            );
        }
    }
    let hashes = derive_prepared_openid4vp_request_hashes(PreparedOpenId4VpRequestInput {
        nonce: &request.nonce,
        audience: &audience,
        query,
        transaction_hashes: &transaction_hashes,
        response_mode,
        response_uri: request.response_uri.as_deref(),
        redirect_uri: request.redirect_uri.as_deref(),
        state: request.state.as_deref(),
        issued_at_unix,
        expires_at_unix,
    })
    .map_err(|_| invalid())?;
    Ok(WalletPreparedPersonaRequest {
        mode: profile,
        hash_strategy,
        claim_name_hash,
        claim_value,
        hashes,
        response_mode,
        issued_at_unix,
        expires_at_unix,
    })
}

/// Wrap the ZK provider's canonical, fully signed prepared presentation in a
/// bounded OpenID4VP `vp_token` value. The verifier independently checks it.
fn encode_zk_prepared_persona_response(
    canonical_presentation: &[u8],
) -> Result<PresentationValue, WalletError> {
    encode_zk_prepared_persona_value(canonical_presentation).map_err(|_| invalid())
}

/// Application provider for a selected prepared persona credential.
///
/// The provider owns proof selection, current issuer status, and holder
/// signing. For a private persona it must durably reserve one fresh token
/// before returning its proof bytes or invoking the one-time signing key.
/// The verifier independently checks every proof and the live signature.
pub trait ZkPersonaCredentialEvidencePresentationProvider {
    /// Build the canonical signed presentation for one authenticated request.
    fn present(
        &mut self,
        request: &WalletPreparedPersonaRequest,
        now_unix: u64,
    ) -> Result<Zeroizing<Vec<u8>>, WalletError>;
}

/// Produce a prepared persona response from an authenticated OpenID4VP request.
///
/// This is the Wallet disclosure boundary. An unavailable provider fails
/// closed; a caller cannot submit raw proof bytes in place of this operation.
pub fn prepare_zk_prepared_persona_response(
    verified_request: &impl WalletAuthorizationRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    now_unix: u64,
    provider: &mut dyn ZkPersonaCredentialEvidencePresentationProvider,
) -> Result<PresentationValue, WalletError> {
    let request = prepare_zk_prepared_persona_request(verified_request, invocation, query_id)?;
    present_prepared_request(&request, now_unix, provider)
}

/// Produce an unsigned DC API prepared response using the browser-origin
/// security context and a verifier-retained time hint.
pub fn prepare_zk_prepared_persona_unsigned_dc_api_response(
    verified_request: &VerifiedUnsignedDcApiRequest,
    invocation: &WalletInvocationContext,
    query_id: &QueryId,
    now_unix: u64,
    provider: &mut dyn ZkPersonaCredentialEvidencePresentationProvider,
) -> Result<PresentationValue, WalletError> {
    let request = prepare_zk_prepared_persona_unsigned_dc_api_request(
        verified_request,
        invocation,
        query_id,
    )?;
    present_prepared_request(&request, now_unix, provider)
}

fn present_prepared_request(
    request: &WalletPreparedPersonaRequest,
    now_unix: u64,
    provider: &mut dyn ZkPersonaCredentialEvidencePresentationProvider,
) -> Result<PresentationValue, WalletError> {
    if now_unix < request.issued_at_unix() || now_unix >= request.expires_at_unix() {
        return Err(invalid());
    }
    let canonical_presentation = provider.present(request, now_unix)?;
    encode_zk_prepared_persona_response(&canonical_presentation)
}

#[cfg(test)]
#[path = "prepare_zk_prepared_persona_tests.rs"]
mod tests;
