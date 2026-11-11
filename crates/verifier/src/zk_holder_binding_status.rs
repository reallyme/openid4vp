// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_credential_status::{
    status_list_signing_payload, validate_status_list, CredentialStatusError,
    CredentialStatusInvalidReason,
};
use reallyme_credential_status::{
    StatusList, StatusListFreshnessPolicy, StatusListVerifier, StatusPurpose,
};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_zk_api::{
    common_root::{
        common_credential_root_issuer_status_root, verify_root_status_snapshot,
        ZkRootStatusSnapshot,
    },
    issuer_status::ZkIssuerStatusPurpose,
};
use reallyme_zk_api::{
    common_root::{
        ZkCommonCredentialRootIssuerStatusExpectation, ZkCommonCredentialRootVerifier,
        ZkRootStatusTrustPolicy, ZkVerifiedRootStatusSnapshot,
    },
    keys::{ZkAttestationPublicKey, ZkIssuerPublicKey},
};
#[cfg(any(feature = "native", feature = "wasm"))]
use sha2::{Digest, Sha256};

use crate::{VerifierError, VerifierErrorReason};

/// Verifier-owned assurance policy for common-credential-root presentations.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootTrustPolicy {
    /// Trusted ReallyMe root-attestation signing key.
    pub attestation_signer: ZkAttestationPublicKey,
    /// Accepted ReallyMe root-assurance policy identifier.
    pub assurance_policy_id: [u8; 32],
    /// Trusted issuer key for each requested credential role.
    pub credential_issuers: [ZkIssuerPublicKey; 2],
    /// Deployment-pinned identity of the active-root feed, stable across
    /// authorized signing-key rotation. A verifier must not derive this from
    /// the holder presentation or the current signing key.
    pub status_feed_id: [u8; 32],
    /// Shared ZK API policy for authority, rollback, and freshness checks.
    pub status: ZkRootStatusTrustPolicy,
}

/// Authenticated, time-bounded common-credential-root verification policy.
#[derive(Clone, Copy)]
pub struct ZkCommonCredentialRootVerificationPolicy<'a> {
    /// Trusted ReallyMe attestation signing key.
    pub(super) attestation_signer: ZkAttestationPublicKey,
    /// Accepted root-assurance policy identifier.
    pub(super) assurance_policy_id: [u8; 32],
    /// Root authenticated by the deployment-pinned status authority.
    pub(super) status: ZkVerifiedRootStatusSnapshot,
    root_status_feed_id: [u8; 32],
    /// Trusted issuer key for each requested credential role.
    pub(super) credential_issuers: [ZkIssuerPublicKey; 2],
    /// Signature-verified, rollback-admitted issuer status for each role.
    pub(super) issuer_status: Option<[ZkVerifiedIssuerStatus; 2]>,
    /// The same durable floors must still admit this observation when used.
    pub(super) root_floor: Option<&'a dyn ZkRootStatusRollbackFloor>,
    pub(super) issuer_floors: Option<[&'a dyn ZkIssuerStatusRollbackFloor; 2]>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ZkVerifiedIssuerStatus {
    pub(super) expectation: ZkCommonCredentialRootIssuerStatusExpectation,
    pub(super) list_key: [u8; 32],
    pub(super) payload_sha256: [u8; 32],
    pub(super) issued_at: u64,
    pub(super) next_update: u64,
    pub(super) max_age_secs: u64,
}

/// Durable floor for each trusted issuer status-list identity.
///
/// Implementations must atomically persist newer issue times and poison
/// same-time conflicting payloads across process restarts. A failed write
/// must reject the list; in-memory implementations are not production floors.
pub trait ZkIssuerStatusRollbackFloor: Send + Sync {
    /// Admit only the latest signature-verified list for this identity.
    fn admit_verified(
        &self,
        list_key: [u8; 32],
        issued_at: u64,
        payload_sha256: [u8; 32],
    ) -> Result<(), VerifierError>;
}

/// Durable floor for the ReallyMe signed active-root sequence.
///
/// A verifier must atomically persist the highest verified sequence and
/// reject same-sequence conflicting snapshots across process restarts.
/// An in-memory floor is suitable only for tests.
pub trait ZkRootStatusRollbackFloor: Send + Sync {
    /// Admit a signature-verified active-root snapshot before using its root.
    fn admit_verified(
        &self,
        feed_id: [u8; 32],
        sequence: u64,
        signing_digest: [u8; 32],
    ) -> Result<(), VerifierError>;
}

/// Verifier-owned inputs for one credential-role status list.
pub struct ZkIssuerStatusTrust<'status, 'floor> {
    /// Current signed list fetched from the issuer's configured source.
    pub list: &'status StatusList,
    /// Exact trusted issuer identifier for this role.
    pub issuer: &'status str,
    /// Trusted status URL signed into this role's credential.
    pub url: &'status str,
    /// Required meaning of set bits.
    pub purpose: StatusPurpose,
    /// Signature verifier with a trusted issuer-key resolver.
    pub verifier: &'status dyn StatusListVerifier,
    /// Deployment freshness ceiling.
    pub freshness: StatusListFreshnessPolicy,
    /// Durable latest-list floor shared across verifier restarts.
    pub floor: &'floor dyn ZkIssuerStatusRollbackFloor,
}

impl<'a> ZkCommonCredentialRootVerificationPolicy<'a> {
    /// Return only status roots admitted from signed, fresh issuer lists.
    ///
    /// This allows a direct API verifier to use the same trust decision as the
    /// OpenID4VP adapter without copying roots from holder-supplied proofs.
    pub fn issuer_status_expectations(
        self,
        now_unix: u64,
    ) -> Result<[ZkCommonCredentialRootIssuerStatusExpectation; 2], VerifierError> {
        self.validate_status_time(now_unix)?;
        let status = self
            .issuer_status
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        Ok([status[0].expectation, status[1].expectation])
    }

    #[cfg(any(feature = "native", feature = "wasm"))]
    pub(super) fn try_from_signed_snapshot(
        trust: ZkCommonCredentialRootTrustPolicy,
        snapshot: ZkRootStatusSnapshot,
        now_unix: u64,
    ) -> Result<Self, VerifierError> {
        if trust.status_feed_id.iter().all(|byte| *byte == 0) {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidRootAssuranceStatus,
            ));
        }
        let status = verify_root_status_snapshot(snapshot, trust.status, now_unix)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRootAssuranceStatus))?;
        Ok(Self {
            attestation_signer: trust.attestation_signer,
            assurance_policy_id: trust.assurance_policy_id,
            status,
            root_status_feed_id: trust.status_feed_id,
            credential_issuers: trust.credential_issuers,
            issuer_status: None,
            root_floor: None,
            issuer_floors: None,
        })
    }

    /// Build policy from a signed ReallyMe snapshot and two signed issuer lists.
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub fn try_from_signed_snapshot_with_issuer_status(
        trust: ZkCommonCredentialRootTrustPolicy,
        snapshot: ZkRootStatusSnapshot,
        root_floor: &'a dyn ZkRootStatusRollbackFloor,
        issuer_status: [ZkIssuerStatusTrust<'_, 'a>; 2],
        now_unix: u64,
    ) -> Result<Self, VerifierError> {
        let mut policy = Self::try_from_signed_snapshot(trust, snapshot, now_unix)?;
        root_floor.admit_verified(
            trust.status_feed_id,
            policy.status.sequence(),
            policy.status.signing_digest(),
        )?;
        let [first, second] = issuer_status;
        let issuer_floors = [first.floor, second.floor];
        policy.issuer_status = Some([
            verify_issuer_status(first, now_unix)?,
            verify_issuer_status(second, now_unix)?,
        ]);
        policy.root_floor = Some(root_floor);
        policy.issuer_floors = Some(issuer_floors);
        Ok(policy)
    }

    pub(super) fn validate_status_time(&self, now_unix: u64) -> Result<(), VerifierError> {
        self.status
            .validate_at(now_unix)
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRootAssuranceStatus))?;
        let issuer_status = self
            .issuer_status
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        for status in issuer_status {
            let local_expiry = status
                .issued_at
                .checked_add(status.max_age_secs)
                .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
            if now_unix < status.issued_at
                || now_unix >= status.next_update
                || now_unix >= local_expiry
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::InvalidCredentialStatus,
                ));
            }
        }
        let root_floor = self
            .root_floor
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidRootAssuranceStatus))?;
        root_floor.admit_verified(
            self.root_status_feed_id,
            self.status.sequence(),
            self.status.signing_digest(),
        )?;
        let issuer_floors = self
            .issuer_floors
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        for (status, floor) in issuer_status.into_iter().zip(issuer_floors) {
            floor.admit_verified(status.list_key, status.issued_at, status.payload_sha256)?;
        }
        Ok(())
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
pub(super) fn verify_issuer_status(
    trust: ZkIssuerStatusTrust<'_, '_>,
    now_unix: u64,
) -> Result<ZkVerifiedIssuerStatus, VerifierError> {
    const STATUS_URL_LIMIT: usize = 2_048;
    const LIST_KEY_DOMAIN: &[u8] = b"ReallyMe issuer status floor v1";
    let list = trust.list;
    if trust.issuer.is_empty()
        || trust.url.is_empty()
        || trust.url.len() > STATUS_URL_LIMIT
        || list.issuer != trust.issuer
        || list.purpose != trust.purpose
    {
        return Err(VerifierError::new(
            VerifierErrorReason::InvalidCredentialStatus,
        ));
    }
    let list_id = list
        .list_id
        .ok_or_else(|| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
    verify_status_list_authenticity(list, now_unix, trust.freshness, trust.verifier)
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
    let payload = status_list_signing_payload(list)
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
    // Do not advance the durable rollback floor for a signed but unusable
    // bitstring. A malformed root must fail before it can poison the last
    // accepted sequence for this issuer list.
    let root = common_credential_root_issuer_status_root(&list.encoded_list, list.length)
        .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
    let mut key_digest = Sha256::new();
    key_digest.update(LIST_KEY_DOMAIN);
    key_digest.update(trust.issuer.as_bytes());
    key_digest.update([0_u8]);
    key_digest.update(trust.url.as_bytes());
    key_digest.update([0_u8]);
    key_digest.update(list_id);
    let list_key: [u8; 32] = key_digest.finalize().into();
    let payload_sha256: [u8; 32] = Sha256::digest(payload.as_slice()).into();
    trust
        .floor
        .admit_verified(list_key, list.issued_at, payload_sha256)?;
    let url_hash: [u8; 32] = Sha256::digest(trust.url.as_bytes()).into();
    let purpose = match trust.purpose {
        StatusPurpose::Revocation => ZkIssuerStatusPurpose::Revocation,
        StatusPurpose::Suspension => ZkIssuerStatusPurpose::Suspension,
        _ => {
            return Err(VerifierError::new(
                VerifierErrorReason::InvalidCredentialStatus,
            ))
        }
    };
    Ok(ZkVerifiedIssuerStatus {
        expectation: ZkCommonCredentialRootIssuerStatusExpectation {
            root,
            length: list.length,
            list_id,
            url_hash,
            purpose,
        },
        list_key,
        payload_sha256,
        issued_at: list.issued_at,
        next_update: list.next_update,
        max_age_secs: trust.freshness.max_age_secs,
    })
}

/// Authenticate a verifier-owned issuer status list and return its ZK fields.
///
/// The signed list is admitted to the durable rollback floor before the root
/// is returned. Callers bind the returned fields to a verified proof; a
/// holder-supplied list or locator is never trust configuration.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn verified_issuer_status_expectation(
    trust: ZkIssuerStatusTrust<'_, '_>,
    now_unix: u64,
) -> Result<ZkCommonCredentialRootIssuerStatusExpectation, VerifierError> {
    verify_issuer_status(trust, now_unix).map(|status| status.expectation)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn verify_status_list_authenticity(
    list: &StatusList,
    now_unix: u64,
    freshness: StatusListFreshnessPolicy,
    verifier: &dyn StatusListVerifier,
) -> Result<(), CredentialStatusError> {
    validate_status_list(list)?;
    if freshness.max_age_secs == 0 {
        return Err(CredentialStatusError::InvalidInput(
            CredentialStatusInvalidReason::InvalidTimeWindow,
        ));
    }
    if now_unix < list.issued_at {
        return Err(CredentialStatusError::NotYetValid);
    }
    let local_expiry = list.issued_at.checked_add(freshness.max_age_secs).ok_or(
        CredentialStatusError::InvalidInput(CredentialStatusInvalidReason::InvalidTimeWindow),
    )?;
    if now_unix >= local_expiry || now_unix >= list.next_update {
        return Err(CredentialStatusError::Expired);
    }

    let payload = status_list_signing_payload(list)?;
    verifier.verify_status_list(
        list.issuer.as_str(),
        list.signature.alg,
        payload.as_slice(),
        list.signature.sig_bytes.as_slice(),
    )
}

impl core::fmt::Debug for ZkCommonCredentialRootVerificationPolicy<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ZkCommonCredentialRootVerificationPolicy")
            .field("attestation_signer", &self.attestation_signer)
            .field("credential_issuer_count", &self.credential_issuers.len())
            .field("assurance_policy_id", &"<redacted>")
            .field("status_root", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy)]
pub(super) struct ZkCommonCredentialRootVerifierConfig<'a> {
    pub(super) verifier: &'a dyn ZkCommonCredentialRootVerifier,
    pub(super) policy: ZkCommonCredentialRootVerificationPolicy<'a>,
}
