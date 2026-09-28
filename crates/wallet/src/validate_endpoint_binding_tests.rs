// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use super::{
    BoundedX509CertificateChain, TrustedX509RequestObjectSigner, VerifiedX509CertificateBinding,
    X509RequestObjectTrustDecision, X509RequestObjectTrustPurpose, X509TrustDecisionContext,
    X509TrustIndeterminateReason, X509TrustRejectionReason, MAX_X509_CERTIFICATE_DER_BYTES,
    MAX_X509_CHAIN_CERTIFICATES, MAX_X509_CHAIN_DER_BYTES, MAX_X509_DNS_SAN_NAMES,
};
use crate::WalletErrorReason;
use reallyme_openid4vp_types::CanonicalDnsName;

const LEAF_DER: &[u8] = b"leaf certificate DER";
const LEAF_KEY: &[u8] = b"leaf public key";

impl VerifiedX509CertificateBinding {
    pub(crate) fn from_leaf_certificate_der(
        dns_sans: Vec<String>,
        leaf_certificate_der: &[u8],
    ) -> Result<Self, crate::WalletError> {
        let mut dns_names = Vec::with_capacity(dns_sans.len());
        for dns_san in dns_sans {
            dns_names.push(CanonicalDnsName::parse_rfc5280_san(&dns_san).map_err(|_| {
                crate::WalletError::new(WalletErrorReason::MalformedX509CertificateChain)
            })?);
        }
        let fingerprint = super::sha256_array(leaf_certificate_der);
        Ok(Self {
            dns_names,
            leaf_certificate_sha256: fingerprint,
            chain_certificate_sha256: vec![fingerprint],
            context: X509TrustDecisionContext::new(1, [1_u8; 32], [2_u8; 32], 0, u64::MAX)?,
        })
    }
}

fn chain() -> BoundedX509CertificateChain {
    BoundedX509CertificateChain::new(vec![LEAF_DER.to_vec(), b"issuer DER".to_vec()])
        .expect("bounded test chain")
}

#[test]
fn bounded_chain_exposes_all_exact_certificates_in_leaf_first_order() {
    let chain = chain();
    let certificates = chain.certificates_der().collect::<Vec<_>>();

    assert_eq!(certificates, vec![LEAF_DER, b"issuer DER"]);
}

fn context(evaluated_at: u64, valid_until: u64) -> X509TrustDecisionContext {
    X509TrustDecisionContext::new(7, [0x11_u8; 32], [0x22_u8; 32], evaluated_at, valid_until)
        .expect("valid test trust context")
}

#[test]
fn rejects_incomplete_trust_provenance() {
    for (source_snapshot, trust_anchor) in [([0_u8; 32], [2_u8; 32]), ([1_u8; 32], [0_u8; 32])] {
        let err = X509TrustDecisionContext::new(7, source_snapshot, trust_anchor, 10, 20)
            .expect_err("trusted context requires both provenance digests");
        assert_eq!(
            err.reason(),
            WalletErrorReason::X509TrustEvidenceUnavailable
        );
    }

    let missing_policy = X509TrustDecisionContext::new(0, [1_u8; 32], [2_u8; 32], 10, 20)
        .expect_err("trusted context requires a nonzero policy version");
    assert_eq!(
        missing_policy.reason(),
        WalletErrorReason::X509TrustEvidenceUnavailable
    );

    let invalid_interval = X509TrustDecisionContext::new(7, [1_u8; 32], [2_u8; 32], 21, 20)
        .expect_err("trusted context requires an ordered validity interval");
    assert_eq!(
        invalid_interval.reason(),
        WalletErrorReason::X509TrustEvidenceStale
    );
}

fn trusted_decision(
    dns_sans: Vec<String>,
    evaluated_at: u64,
    valid_until: u64,
) -> X509RequestObjectTrustDecision {
    let signer = TrustedX509RequestObjectSigner::new(
        chain(),
        LEAF_KEY.to_vec(),
        dns_sans,
        context(evaluated_at, valid_until),
    )
    .expect("valid test trusted signer");
    X509RequestObjectTrustDecision::Trusted(signer)
}

#[test]
fn receipt_retains_exact_chain_and_versioned_wrpac_provenance() {
    let receipt = VerifiedX509CertificateBinding::from_trust_decision(
        trusted_decision(vec!["Verifier.Example".to_owned()], 10, 20),
        LEAF_KEY,
        15,
    )
    .expect("fresh signer-bound trust decision");

    assert_eq!(receipt.chain_certificate_sha256().len(), 2);
    assert_eq!(
        receipt.leaf_certificate_sha256(),
        &receipt.chain_certificate_sha256()[0]
    );
    assert_eq!(receipt.trust_context().policy_version(), 7);
    assert_eq!(
        receipt.trust_context().purpose(),
        X509RequestObjectTrustPurpose::WalletRelyingPartyAccessCertificate
    );
    assert_eq!(
        receipt.trust_context().source_snapshot_sha256(),
        &[0x11; 32]
    );
    assert_eq!(receipt.trust_context().trust_anchor_sha256(), &[0x22; 32]);
    assert_eq!(receipt.trust_context().evaluated_at_unix(), 10);
    assert_eq!(receipt.trust_context().valid_until_unix(), 20);
}

#[test]
fn rejects_leaf_key_mismatch_before_constructing_receipt() {
    let err = VerifiedX509CertificateBinding::from_trust_decision(
        trusted_decision(Vec::new(), 10, 20),
        b"different key",
        15,
    )
    .expect_err("JWS key must be the trusted leaf key");

    assert_eq!(err.reason(), WalletErrorReason::X509LeafKeyMismatch);
}

#[test]
fn rejects_stale_and_not_yet_valid_trust_receipts() {
    for now_unix in [9, 21] {
        let err = VerifiedX509CertificateBinding::from_trust_decision(
            trusted_decision(Vec::new(), 10, 20),
            LEAF_KEY,
            now_unix,
        )
        .expect_err("trust receipt outside its interval is stale");
        assert_eq!(err.reason(), WalletErrorReason::X509TrustEvidenceStale);
    }
}

#[test]
fn preserves_rejected_versus_indeterminate_trust_outcomes() {
    let rejected = VerifiedX509CertificateBinding::from_trust_decision(
        X509RequestObjectTrustDecision::Rejected(X509TrustRejectionReason::PathRejected),
        LEAF_KEY,
        15,
    )
    .expect_err("rejected path fails closed");
    assert_eq!(
        rejected.reason(),
        WalletErrorReason::X509CertificatePathRejected
    );

    let unavailable = VerifiedX509CertificateBinding::from_trust_decision(
        X509RequestObjectTrustDecision::Indeterminate(
            X509TrustIndeterminateReason::EvidenceUnavailable,
        ),
        LEAF_KEY,
        15,
    )
    .expect_err("indeterminate trust fails closed");
    assert_eq!(
        unavailable.reason(),
        WalletErrorReason::X509TrustEvidenceUnavailable
    );
}

#[test]
fn rejects_wildcard_certificate_san_for_exact_client_identifier_binding() {
    let err = TrustedX509RequestObjectSigner::new(
        chain(),
        LEAF_KEY.to_vec(),
        vec!["*.example".to_owned()],
        context(10, 20),
    )
    .expect_err("RFC 8399 exact dNSName equality does not use TLS wildcards");

    assert_eq!(
        err.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );
}

#[test]
fn rejects_unbounded_or_malformed_dns_san_evidence_at_trust_boundary() {
    let too_many = vec!["verifier.example".to_owned(); MAX_X509_DNS_SAN_NAMES + 1];
    let too_many_error =
        TrustedX509RequestObjectSigner::new(chain(), LEAF_KEY.to_vec(), too_many, context(10, 20))
            .expect_err("excessive DNS SAN count is rejected before receipt construction");
    assert_eq!(
        too_many_error.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );

    let malformed_a_label_error = TrustedX509RequestObjectSigner::new(
        chain(),
        LEAF_KEY.to_vec(),
        vec!["xn--a.example".to_owned()],
        context(10, 20),
    )
    .expect_err("malformed RFC 8399 A-label is rejected at the trust boundary");
    assert_eq!(
        malformed_a_label_error.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );
}

#[test]
fn enforces_x5c_count_and_certificate_size_bounds() {
    let too_many = vec![vec![1_u8]; MAX_X509_CHAIN_CERTIFICATES + 1];
    let err = BoundedX509CertificateChain::new(too_many)
        .expect_err("excessive certificate count is rejected");
    assert_eq!(
        err.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );

    let oversized = vec![vec![2_u8; MAX_X509_CERTIFICATE_DER_BYTES + 1]];
    let err =
        BoundedX509CertificateChain::new(oversized).expect_err("oversized certificate is rejected");
    assert_eq!(
        err.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );

    let certificate_count = MAX_X509_CHAIN_DER_BYTES
        .checked_div(MAX_X509_CERTIFICATE_DER_BYTES)
        .and_then(|count| count.checked_add(1))
        .expect("test constants produce a bounded certificate count");
    assert!(certificate_count <= MAX_X509_CHAIN_CERTIFICATES);
    let excessive_aggregate = vec![vec![3_u8; MAX_X509_CERTIFICATE_DER_BYTES]; certificate_count];
    let err = BoundedX509CertificateChain::new(excessive_aggregate)
        .expect_err("excessive aggregate DER length is rejected");
    assert_eq!(
        err.reason(),
        WalletErrorReason::MalformedX509CertificateChain
    );
}
