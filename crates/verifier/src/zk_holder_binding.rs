// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP adapter for the API-owned production proof contracts.

use reallyme_openid4vp_dcql::CredentialFormat;
use reallyme_openid4vp_formats::{build_zk_presentation_binding, parse_zk_presentation_value};
use reallyme_openid4vp_types::{PresentationValue, TransactionDataHashAlgorithm};
use reallyme_zk_api::{
    claim_bundle::MAX_PRESENTATION_LIFETIME_SECONDS,
    claim_bundle::{
        verify_status_qualified_claim_proof_bundle_with, ZkPresentationBoundClaimBundleVerifier,
        ZkPresentationBoundClaimBundleVerifyRequest,
        ZkStatusQualifiedClaimProofBundleVerifyRequest,
    },
    common_root::{
        verify_common_credential_root_with, ZkCommonCredentialRootClaimExpectation,
        ZkCommonCredentialRootJoinPolicy, ZkCommonCredentialRootProof,
        ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootVerifier,
        ZkCommonCredentialRootVerifyRequest,
    },
    issuer_status::ZkIssuerCredentialStatusVerifier,
    issuer_status::{ZkIssuerStatusAuthority, ZkIssuerStatusPurpose},
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding},
};
use subtle::ConstantTimeEq;

use crate::holder_binding::expected_holder_binding_audience;
use crate::{
    HolderBindingClaims, HolderBindingVerificationContext, HolderBindingVerifier,
    VerifiedDisclosureSet, VerifiedHolderBinding, VerifiedTrustProvenance, VerifiedZkClaim,
    VerifiedZkCommonCredentialRootClaim, VerifiedZkCommonCredentialRootPresentation, VerifierError,
    VerifierErrorReason,
};

#[path = "zk_holder_binding_prepared.rs"]
mod prepared;
#[path = "zk_holder_binding_query.rs"]
mod query;
#[path = "zk_holder_binding_status.rs"]
mod status;
pub use prepared::{
    ZkPersonaCredentialEvidenceProofVerifier, ZkPersonaCredentialEvidenceVerifyRequest,
};

use query::{
    build_bundle, build_common_credential_root_proofs, build_issuer_credential_status_proof,
    common_credential_root_persona_mode_from_meta, invalid_zk,
    parse_common_credential_root_query_policy, parse_query_policy, transaction_data_hash,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use status::verified_issuer_status_expectation;
use status::ZkCommonCredentialRootVerifierConfig;
pub use status::{
    ZkCommonCredentialRootTrustPolicy, ZkCommonCredentialRootVerificationPolicy,
    ZkIssuerStatusRollbackFloor, ZkIssuerStatusTrust, ZkRootStatusRollbackFloor,
};

/// Verifies one exact ZK claim requested by a versioned DCQL credential query.
///
/// The query's `meta` has three required string members: `profile`,
/// `hash_strategy`, and `claim_name_hash` (64 lowercase hex characters).
/// Optional `claim_value_b64u` requires one exact 1–64-byte value. When it is
/// absent, the verified bytes are disclosed to the caller. A v1 query cannot
/// request additional claim paths or claim sets.
/// Issuer trust is supplied by the deployment rather than by the presentation.
/// The common-credential-root profile requires issuer-signed validity and current status.
pub struct ZkHolderBindingVerifier<'a> {
    bundle_verifier: &'a dyn ZkPresentationBoundClaimBundleVerifier,
    trusted_issuers: &'a [ZkIssuerPublicKey],
    requirements: ZkVerificationRequirements,
    common_credential_root: Option<ZkCommonCredentialRootVerifierConfig<'a>>,
    persona_credential_evidence: Option<&'a dyn ZkPersonaCredentialEvidenceProofVerifier>,
    issuer_status: Option<ZkIssuerCredentialStatusVerifierConfig<'a>>,
}

struct ZkIssuerCredentialStatusVerifierConfig<'a> {
    verifier: &'a dyn ZkIssuerCredentialStatusVerifier,
    authority: &'a dyn ZkIssuerStatusAuthority,
    purpose: ZkIssuerStatusPurpose,
}

/// Deployment assurance requirements for a ZK credential presentation.
///
/// The direct-claim bundle does not establish issuer-signed validity or
/// credential status. The common-credential-root profile requires both properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkVerificationRequirements {
    /// Require an issuer-signed credential validity interval.
    pub issuer_signed_validity: bool,
    /// Require an authenticated credential status decision.
    pub credential_status: bool,
}

impl<'a> ZkHolderBindingVerifier<'a> {
    /// Bind proof verification to the deployment's reviewed backend and issuer keys.
    #[must_use]
    pub const fn new(
        bundle_verifier: &'a dyn ZkPresentationBoundClaimBundleVerifier,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        requirements: ZkVerificationRequirements,
    ) -> Self {
        Self {
            bundle_verifier,
            trusted_issuers,
            requirements,
            common_credential_root: None,
            persona_credential_evidence: None,
            issuer_status: None,
        }
    }

    /// Bind proof verification to both legacy bundles and common-credential-root policy.
    #[must_use]
    pub const fn new_with_common_credential_root(
        bundle_verifier: &'a dyn ZkPresentationBoundClaimBundleVerifier,
        trusted_issuers: &'a [ZkIssuerPublicKey],
        requirements: ZkVerificationRequirements,
        common_credential_root_verifier: &'a dyn ZkCommonCredentialRootVerifier,
        common_credential_root_policy: ZkCommonCredentialRootVerificationPolicy<'a>,
    ) -> Self {
        Self {
            bundle_verifier,
            trusted_issuers,
            requirements,
            common_credential_root: Some(ZkCommonCredentialRootVerifierConfig {
                verifier: common_credential_root_verifier,
                policy: common_credential_root_policy,
            }),
            persona_credential_evidence: None,
            issuer_status: None,
        }
    }

    /// Supply the product verifier that checks prepared proofs, current status,
    /// holder authentication, and durable replay state before returning.
    #[must_use]
    pub fn with_persona_credential_evidence(
        mut self,
        verifier: &'a dyn ZkPersonaCredentialEvidenceProofVerifier,
    ) -> Self {
        self.persona_credential_evidence = Some(verifier);
        self
    }

    /// Supply the pinned fifth-proof verifier and independently authenticated
    /// current issuer feed for direct and private request-bound claims.
    #[must_use]
    pub fn with_issuer_credential_status(
        mut self,
        verifier: &'a dyn ZkIssuerCredentialStatusVerifier,
        authority: &'a dyn ZkIssuerStatusAuthority,
        purpose: ZkIssuerStatusPurpose,
    ) -> Self {
        self.issuer_status = Some(ZkIssuerCredentialStatusVerifierConfig {
            verifier,
            authority,
            purpose,
        });
        self
    }
}

impl HolderBindingVerifier for ZkHolderBindingVerifier<'_> {
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        let query = context.credential_query();
        if query.format.as_str() != CredentialFormat::REALLYME_ZK_V1
            || !query.require_cryptographic_holder_binding
            || query.claims.is_some()
            || query.claim_sets.is_some()
            || query.trusted_authorities.is_some()
        {
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenQueryMismatch,
            ));
        }
        if query::evidence_mode_from_meta(&query.meta).is_some() {
            return self.verify_prepared_holder_binding(presentation, context);
        }
        if common_credential_root_persona_mode_from_meta(&query.meta).is_some() {
            return self.verify_common_credential_root_holder_binding(presentation, context);
        }
        if !self.requirements.issuer_signed_validity || !self.requirements.credential_status {
            return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
        }
        let issuer_status = self
            .issuer_status
            .as_ref()
            .ok_or(VerifierError::new(VerifierErrorReason::UnsupportedFormat))?;
        let policy = parse_query_policy(&query.meta)?;
        let presentation = parse_zk_presentation_value(presentation)
            .map_err(|_| invalid_zk())?
            .ok_or_else(invalid_zk)?;
        // Free-form labels cannot be promoted to authenticated claims. The
        // v1 query matches only the claim bytes minted by the bundle verifier.
        if !presentation.derived_claims.is_empty()
            || presentation.profile != policy.presentation_profile
        {
            return Err(invalid_zk());
        }

        let audience = expected_holder_binding_audience(&context.session().binding);
        let transaction_data_hash = transaction_data_hash(context)?;
        let expected = build_zk_presentation_binding(
            &context.session().binding.nonce,
            &audience,
            transaction_data_hash,
        );
        if presentation.binding != expected {
            return Err(invalid_zk());
        }
        let binding = ZkSessionBinding {
            nonce_hash: expected.nonce_hash,
            audience_hash: expected.audience_hash,
            transaction_data_hash: expected.transaction_data_hash,
        };
        let bundle = build_bundle(
            &presentation,
            policy.bundle_kind,
            policy.hash_strategy,
            binding,
        )?;
        let status_proof =
            build_issuer_credential_status_proof(&presentation, policy.hash_strategy)?;
        let request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
            &bundle,
            ZkProofSuite::PRODUCTION,
            binding,
            self.trusted_issuers,
            context.now_unix(),
        )
        .map_err(|_| invalid_zk())?;
        let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
            request,
            &status_proof,
            issuer_status.authority,
            issuer_status.purpose,
        )
        .map_err(|_| invalid_zk())?;
        let verified = verify_status_qualified_claim_proof_bundle_with(
            self.bundle_verifier,
            issuer_status.verifier,
            request,
        )
        .map_err(|_| invalid_zk())?;
        let statement = verified.statement();
        if !bool::from(statement.claim_name_hash().ct_eq(&policy.claim_name_hash))
            || policy
                .claim_value
                .as_ref()
                .is_some_and(|value| !bool::from(statement.claim_value().ct_eq(value.as_slice())))
            || statement.presentation_expiry_unix() > context.session().binding.expiry_unix
        {
            return Err(invalid_zk());
        }
        let transaction_data_hashes = transaction_data_hash.into_iter().collect();
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec![audience],
                nonce: context.session().binding.nonce.clone(),
                expiration_unix: statement.presentation_expiry_unix(),
                issued_at_unix: 0,
                sd_hash: None,
                transaction_data_hashes,
                transaction_data_hashes_alg: transaction_data_hash
                    .map(|_| TransactionDataHashAlgorithm::Sha256),
            },
            VerifiedDisclosureSet::ZkClaim(Box::new(VerifiedZkClaim::from_verified(
                verified.bundle_kind(),
                policy.hash_strategy,
                statement,
            ))),
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}

impl ZkHolderBindingVerifier<'_> {
    fn verify_common_credential_root_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        let Some(config) = self.common_credential_root else {
            return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
        };
        config.policy.validate_status_time(context.now_unix())?;
        let issuer_status = config
            .policy
            .issuer_status
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        let query_policy =
            parse_common_credential_root_query_policy(&context.credential_query().meta)?;
        let presentation = parse_zk_presentation_value(presentation)
            .map_err(|_| invalid_zk())?
            .ok_or_else(invalid_zk)?;
        if !presentation.derived_claims.is_empty()
            || presentation.profile != query_policy.presentation_profile
        {
            return Err(invalid_zk());
        }

        let audience = expected_holder_binding_audience(&context.session().binding);
        let transaction_data_hash = transaction_data_hash(context)?;
        let expected = build_zk_presentation_binding(
            &context.session().binding.nonce,
            &audience,
            transaction_data_hash,
        );
        if presentation.binding != expected {
            return Err(invalid_zk());
        }
        let binding = ZkSessionBinding {
            nonce_hash: expected.nonce_hash,
            audience_hash: expected.audience_hash,
            transaction_data_hash: expected.transaction_data_hash,
        };
        let proofs = build_common_credential_root_proofs(
            &presentation,
            query_policy.persona_mode,
            query_policy.hash_strategy,
        )?;
        let status_validation_time = accepted_status_validation_time(
            proofs.as_slice(),
            context.session().binding.request_time_unix,
            context.now_unix(),
        )?;
        // The proof time can differ from this verifier's clock. Accept it only
        // while the independently authenticated root and both issuer lists
        // were valid; proof verification below binds the field cryptographically.
        config.policy.validate_status_time(status_validation_time)?;
        let join_policy = ZkCommonCredentialRootJoinPolicy {
            challenge: binding.nonce_hash,
            audience_hash: binding.audience_hash,
            transaction_data_hash: binding.transaction_data_public_input(),
            request_time_unix: context.session().binding.request_time_unix,
            status_validation_time_unix: context.now_unix(),
            status_validation_max_age_seconds: MAX_PRESENTATION_LIFETIME_SECONDS,
            attestation_signer: config.policy.attestation_signer,
            assurance_policy_id: config.policy.assurance_policy_id,
            status_root: config.policy.status.root(),
            claims: [
                ZkCommonCredentialRootClaimExpectation {
                    issuer: config.policy.credential_issuers[0],
                    claim_name_hash: query_policy.first_claim_name_hash,
                    value: query_policy.first_claim_value.as_slice(),
                },
                ZkCommonCredentialRootClaimExpectation {
                    issuer: config.policy.credential_issuers[1],
                    claim_name_hash: query_policy.second_claim_name_hash,
                    value: query_policy.second_claim_value.as_slice(),
                },
            ],
            issuer_status: [issuer_status[0].expectation, issuer_status[1].expectation],
            persona_mode: query_policy.persona_mode,
        };
        let request = ZkCommonCredentialRootVerifyRequest::try_new(
            query_policy.persona_mode,
            query_policy.hash_strategy,
            ZkProofSuite::PRODUCTION,
            binding,
            proofs.as_slice(),
            join_policy,
        )
        .map_err(|_| invalid_zk())?;
        let expiration_unix = request.session_expiry_unix().map_err(|_| invalid_zk())?;
        if expiration_unix <= context.now_unix()
            || expiration_unix > context.session().binding.expiry_unix
        {
            return Err(invalid_zk());
        }
        let verified = verify_common_credential_root_with(config.verifier, request)
            .map_err(|_| invalid_zk())?;
        // Proof generation and verification can be long enough for a newer
        // signed revocation snapshot to advance a floor concurrently. The
        // decision must still use the latest locally observed status.
        config.policy.validate_status_time(context.now_unix())?;
        let transaction_data_hashes = transaction_data_hash.into_iter().collect();
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec![audience],
                nonce: context.session().binding.nonce.clone(),
                expiration_unix,
                issued_at_unix: 0,
                sd_hash: None,
                transaction_data_hashes,
                transaction_data_hashes_alg: transaction_data_hash
                    .map(|_| TransactionDataHashAlgorithm::Sha256),
            },
            VerifiedDisclosureSet::ZkCommonCredentialRoot(Box::new(
                VerifiedZkCommonCredentialRootPresentation::from_verified(
                    verified.persona_mode(),
                    query_policy.hash_strategy,
                    verified.verified_proof_count(),
                    [
                        VerifiedZkCommonCredentialRootClaim::from_verified(
                            config.policy.credential_issuers[0],
                            query_policy.first_claim_name_hash,
                            query_policy.first_claim_value.as_slice(),
                        ),
                        VerifiedZkCommonCredentialRootClaim::from_verified(
                            config.policy.credential_issuers[1],
                            query_policy.second_claim_name_hash,
                            query_policy.second_claim_value.as_slice(),
                        ),
                    ],
                ),
            )),
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}

fn accepted_status_validation_time(
    proofs: &[ZkCommonCredentialRootProof],
    request_time_unix: u64,
    now_unix: u64,
) -> Result<u64, VerifierError> {
    let first = proofs
        .get(usize::from(
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0.index(),
        ))
        .ok_or_else(invalid_zk)?;
    let second = proofs
        .get(usize::from(
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1.index(),
        ))
        .ok_or_else(invalid_zk)?;
    let status_time = first
        .public_inputs()
        .issuer_status_validation_time_unix()
        .map_err(|_| invalid_zk())?;
    let second_time = second
        .public_inputs()
        .issuer_status_validation_time_unix()
        .map_err(|_| invalid_zk())?;
    if status_time != second_time {
        return Err(invalid_zk());
    }
    validate_status_proof_time(status_time, request_time_unix, now_unix)?;
    Ok(status_time)
}

fn validate_status_proof_time(
    status_time_unix: u64,
    request_time_unix: u64,
    now_unix: u64,
) -> Result<(), VerifierError> {
    if request_time_unix == 0
        || request_time_unix > now_unix
        || status_time_unix < request_time_unix
        || status_time_unix > now_unix
    {
        return Err(invalid_zk());
    }
    Ok(())
}

#[cfg(test)]
#[path = "zk_holder_binding_prepared_tests.rs"]
mod prepared_tests;
#[cfg(test)]
#[path = "zk_holder_binding_tests.rs"]
mod tests;
