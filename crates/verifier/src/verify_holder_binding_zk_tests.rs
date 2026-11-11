// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::VerifiedZkClaim;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm, claim_bundle::ZkClaimProofBundleKind,
    keys::ZkIssuerPublicKey,
};
use zeroize::Zeroizing;

fn claim() -> VerifiedZkClaim {
    VerifiedZkClaim {
        bundle_kind: ZkClaimProofBundleKind::PrivatePersonaClaimV1,
        hash_strategy: ZkCredentialHashAlgorithm::Sha256,
        issuer: ZkIssuerPublicKey {
            x: [1_u8; 32],
            y: [2_u8; 32],
        },
        persona: None,
        credential_binding: [3_u8; 32],
        session_link_commitment: [4_u8; 32],
        claim_name_hash: [5_u8; 32],
        claim_value: Zeroizing::new(vec![6_u8]),
    }
}

#[test]
fn compatible_verified_claims_can_share_a_presenting_key() {
    let first = claim();
    let mut second = claim();
    second.credential_binding = [7_u8; 32];
    second.claim_name_hash = [8_u8; 32];
    second.claim_value = Zeroizing::new(vec![9_u8]);
    assert!(first.same_presenting_key_in_session(&second));
}

#[test]
fn changed_profile_lane_or_session_commitment_is_inconclusive() {
    let first = claim();
    let mut second = claim();
    second.bundle_kind = ZkClaimProofBundleKind::CredentialSubjectClaimV1;
    assert!(!first.same_presenting_key_in_session(&second));
    second.bundle_kind = first.bundle_kind;
    second.hash_strategy = ZkCredentialHashAlgorithm::Poseidon2;
    assert!(!first.same_presenting_key_in_session(&second));
    second.hash_strategy = first.hash_strategy;
    second.session_link_commitment = [10_u8; 32];
    assert!(!first.same_presenting_key_in_session(&second));
}
