// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prepared-persona verification against the retained OpenID4VP session.

use reallyme_openid4vp_formats::{
    derive_prepared_openid4vp_request_hashes, parse_zk_prepared_persona_value,
    PreparedOpenId4VpRequestHashes, PreparedOpenId4VpRequestInput,
};
use reallyme_openid4vp_types::{PresentationValue, ResponseMode, TransactionDataHashAlgorithm};
use reallyme_zk_api::{
    ZkHashStrategy, ZkPersonaCredentialEvidenceProfile, ZkVerifiedPersonaCredentialEvidence,
};

use crate::holder_binding::expected_holder_binding_audience;
use crate::{
    HolderBindingClaims, HolderBindingVerificationContext, VerifiedDisclosureSet,
    VerifiedHolderBinding, VerifiedTrustProvenance, VerifiedZkPersonaCredentialEvidenceClaim,
    VerifierError, VerifierErrorReason, ZkHolderBindingVerifier,
};

use super::query::parse_prepared_query_policy;

/// All verifier-owned inputs required by the core prepared acceptance check.
/// The implementation must verify both exact proofs, issuer trust, current
/// signed status with rollback protection, live holder signature, the exact
/// `PreparedVerifierRequest`, and durable nonce consumption before success.
pub struct ZkPersonaCredentialEvidenceVerifyRequest<'a> {
    /// Canonical ZK prepared-presentation protobuf from the response.
    pub presentation_bytes: &'a [u8],
    /// Profile selected by the authenticated DCQL query.
    pub profile: ZkPersonaCredentialEvidenceProfile,
    /// Hash lane selected by the authenticated DCQL query.
    pub hash_strategy: ZkHashStrategy,
    /// Exact selected claim-name hash.
    pub claim_name_hash: &'a [u8; 32],
    /// Exact value required by the verifier.
    pub claim_value: &'a [u8],
    /// Session-derived protobuf request digest inputs.
    pub request_hashes: &'a PreparedOpenId4VpRequestHashes,
    /// Negotiated response mode included in the live signature transcript.
    pub response_mode: ResponseMode,
    /// Authenticated request issuance time.
    pub issued_at_unix: u64,
    /// Authenticated request exclusive expiry.
    pub expires_at_unix: u64,
    /// Verifier's trusted current time.
    pub now_unix: u64,
}

/// Injected complete prepared-persona verifier for the product's trust policy.
/// A parser or proof-only adapter must not implement this success boundary.
pub trait ZkPersonaCredentialEvidenceProofVerifier: Send + Sync {
    /// Return authenticated evidence only after complete presentation acceptance.
    fn verify_persona_credential_evidence(
        &self,
        request: ZkPersonaCredentialEvidenceVerifyRequest<'_>,
    ) -> Result<ZkVerifiedPersonaCredentialEvidence, VerifierError>;
}

impl ZkHolderBindingVerifier<'_> {
    pub(super) fn verify_prepared_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        let verifier = self
            .persona_credential_evidence
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::UnsupportedFormat))?;
        let policy = parse_prepared_query_policy(&context.credential_query().meta)?;
        let bytes = parse_zk_prepared_persona_value(presentation)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?;
        let session = context.session();
        let binding = &session.binding;
        let audience = expected_holder_binding_audience(binding);
        let transaction_hashes: Vec<[u8; 32]> = binding
            .transaction_data_bindings
            .iter()
            .filter(|entry| entry.query_id == context.credential_query().id)
            .map(|entry| entry.digest)
            .collect();
        let hashes = derive_prepared_openid4vp_request_hashes(PreparedOpenId4VpRequestInput {
            nonce: &binding.nonce,
            audience: &audience,
            query: context.credential_query(),
            transaction_hashes: &transaction_hashes,
            response_mode: session.response_mode,
            response_uri: binding.response_uri.as_deref(),
            redirect_uri: binding.redirect_uri.as_deref(),
            state: session.state.as_deref(),
            issued_at_unix: binding.request_time_unix,
            expires_at_unix: binding.expiry_unix,
        })
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
        let verified = verifier.verify_persona_credential_evidence(
            ZkPersonaCredentialEvidenceVerifyRequest {
                presentation_bytes: &bytes,
                profile: policy.profile,
                hash_strategy: policy.hash_strategy,
                claim_name_hash: &policy.claim_name_hash,
                claim_value: &policy.claim_value,
                request_hashes: &hashes,
                response_mode: session.response_mode,
                issued_at_unix: binding.request_time_unix,
                expires_at_unix: binding.expiry_unix,
                now_unix: context.now_unix(),
            },
        )?;
        if verified.profile() != policy.profile
            || verified.hash_strategy() != policy.hash_strategy
            || verified
                .proof_window()
                .validate_at(context.now_unix())
                .is_err()
        {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidZkPresentation,
            ));
        }
        let transaction_data_hashes_alg = if transaction_hashes.is_empty() {
            None
        } else {
            Some(TransactionDataHashAlgorithm::Sha256)
        };
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec![audience],
                nonce: binding.nonce.clone(),
                expiration_unix: binding.expiry_unix,
                issued_at_unix: binding.request_time_unix,
                sd_hash: None,
                transaction_data_hashes: transaction_hashes,
                transaction_data_hashes_alg,
            },
            VerifiedDisclosureSet::ZkPersonaCredentialEvidence(Box::new(
                VerifiedZkPersonaCredentialEvidenceClaim::from_verified(
                    policy.profile,
                    policy.hash_strategy,
                    verified.holder_key(),
                    policy.claim_name_hash,
                    &policy.claim_value,
                ),
            )),
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}
