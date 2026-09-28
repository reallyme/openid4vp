// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{CanonicalDnsName, MAX_DNS_NAME_BYTES};
use secrecy::ExposeSecret;
use secrecy::SecretSlice;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{WalletError, WalletErrorReason};

/// Maximum number of certificates permitted in a Request Object `x5c` chain.
pub const MAX_X509_CHAIN_CERTIFICATES: usize = 8;
/// Maximum DER length of one certificate in a Request Object `x5c` chain.
pub const MAX_X509_CERTIFICATE_DER_BYTES: usize = 16 * 1024;
/// Maximum aggregate DER length of a Request Object `x5c` chain.
pub const MAX_X509_CHAIN_DER_BYTES: usize = 64 * 1024;
/// Maximum number of DNS SAN identities retained from the leaf certificate.
pub const MAX_X509_DNS_SAN_NAMES: usize = 64;
/// Maximum aggregate encoded length of retained DNS SAN identities.
/// This independent cap prevents future changes from making the trust boundary unbounded.
pub const MAX_X509_DNS_SAN_BYTES: usize = 16_192;
const MAX_X509_LEAF_PUBLIC_KEY_BYTES: usize = 8 * 1024;

/// Trust purpose required for OpenID4VP X.509 Request Object signers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509RequestObjectTrustPurpose {
    /// EUDI Wallet Relying Party Access Certificate trust.
    WalletRelyingPartyAccessCertificate,
}

/// Non-PII evidence identifying the trust policy decision used for a signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509TrustDecisionContext {
    purpose: X509RequestObjectTrustPurpose,
    policy_version: u32,
    source_snapshot_sha256: [u8; 32],
    trust_anchor_sha256: [u8; 32],
    evaluated_at_unix: u64,
    valid_until_unix: u64,
}

impl X509TrustDecisionContext {
    /// Construct a versioned WRPAC trust context from an accepted trust decision.
    pub fn new(
        policy_version: u32,
        mut source_snapshot_sha256: [u8; 32],
        mut trust_anchor_sha256: [u8; 32],
        evaluated_at_unix: u64,
        valid_until_unix: u64,
    ) -> Result<Self, WalletError> {
        let missing_source_snapshot = bool::from(source_snapshot_sha256.ct_eq(&[0_u8; 32]));
        let missing_trust_anchor = bool::from(trust_anchor_sha256.ct_eq(&[0_u8; 32]));
        if policy_version == 0 || missing_source_snapshot || missing_trust_anchor {
            source_snapshot_sha256.zeroize();
            trust_anchor_sha256.zeroize();
            return Err(WalletError::new(
                WalletErrorReason::X509TrustEvidenceUnavailable,
            ));
        }
        if evaluated_at_unix > valid_until_unix {
            source_snapshot_sha256.zeroize();
            trust_anchor_sha256.zeroize();
            return Err(WalletError::new(WalletErrorReason::X509TrustEvidenceStale));
        }
        Ok(Self {
            purpose: X509RequestObjectTrustPurpose::WalletRelyingPartyAccessCertificate,
            policy_version,
            source_snapshot_sha256,
            trust_anchor_sha256,
            evaluated_at_unix,
            valid_until_unix,
        })
    }

    #[cfg_attr(not(feature = "jose"), allow(dead_code))]
    fn is_fresh_at(&self, now_unix: u64) -> bool {
        self.evaluated_at_unix <= now_unix && now_unix <= self.valid_until_unix
    }

    /// Return the certificate trust purpose.
    #[must_use]
    pub const fn purpose(&self) -> X509RequestObjectTrustPurpose {
        self.purpose
    }

    /// Return the deployment-defined immutable policy revision.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Return the digest of the accepted trust-source snapshot.
    #[must_use]
    pub const fn source_snapshot_sha256(&self) -> &[u8; 32] {
        &self.source_snapshot_sha256
    }

    /// Return the digest identifying the selected trust anchor.
    #[must_use]
    pub const fn trust_anchor_sha256(&self) -> &[u8; 32] {
        &self.trust_anchor_sha256
    }

    /// Return the trusted evaluation time.
    #[must_use]
    pub const fn evaluated_at_unix(&self) -> u64 {
        self.evaluated_at_unix
    }

    /// Return the last time at which the decision may be consumed.
    #[must_use]
    pub const fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }
}

impl Zeroize for X509TrustDecisionContext {
    fn zeroize(&mut self) {
        self.policy_version.zeroize();
        self.source_snapshot_sha256.zeroize();
        self.trust_anchor_sha256.zeroize();
        self.evaluated_at_unix.zeroize();
        self.valid_until_unix.zeroize();
    }
}

impl Drop for X509TrustDecisionContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for X509TrustDecisionContext {}

/// Structurally validated, bounded `x5c` certificate chain in leaf-first order.
#[derive(Clone)]
pub struct BoundedX509CertificateChain {
    certificates_der: Vec<Zeroizing<Vec<u8>>>,
}

impl BoundedX509CertificateChain {
    /// Validate fixed count, per-certificate, and aggregate bounds.
    pub fn new(mut certificates_der: Vec<Vec<u8>>) -> Result<Self, WalletError> {
        if certificates_der.is_empty() || certificates_der.len() > MAX_X509_CHAIN_CERTIFICATES {
            certificates_der.zeroize();
            return Err(WalletError::new(
                WalletErrorReason::MalformedX509CertificateChain,
            ));
        }
        if validated_chain_total_bytes(&certificates_der).is_none() {
            certificates_der.zeroize();
            return Err(WalletError::new(
                WalletErrorReason::MalformedX509CertificateChain,
            ));
        }
        let bounded = certificates_der.into_iter().map(Zeroizing::new).collect();
        Ok(Self {
            certificates_der: bounded,
        })
    }

    /// Return the exact DER leaf certificate from the JOSE header.
    #[must_use]
    pub fn leaf_der(&self) -> &[u8] {
        self.certificates_der
            .first()
            .map_or(&[], |certificate| certificate.as_slice())
    }

    /// Iterate over the exact bounded DER certificates in leaf-first order.
    ///
    /// The iterator preserves the size and count validation performed by
    /// [`Self::new`] while allowing a trust adapter to validate the complete
    /// chain without copying it or reaching into private representation.
    pub fn certificates_der(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.certificates_der
            .iter()
            .map(|certificate| certificate.as_slice())
    }

    #[cfg_attr(not(feature = "jose"), allow(dead_code))]
    fn fingerprints_sha256(&self) -> Vec<[u8; 32]> {
        self.certificates_der
            .iter()
            .map(|certificate| sha256_array(certificate.as_slice()))
            .collect()
    }
}

fn validated_chain_total_bytes(certificates_der: &[Vec<u8>]) -> Option<usize> {
    let mut total_der_bytes = 0_usize;
    for certificate_der in certificates_der {
        if certificate_der.is_empty() || certificate_der.len() > MAX_X509_CERTIFICATE_DER_BYTES {
            return None;
        }
        total_der_bytes = total_der_bytes.checked_add(certificate_der.len())?;
        if total_der_bytes > MAX_X509_CHAIN_DER_BYTES {
            return None;
        }
    }
    Some(total_der_bytes)
}

impl fmt::Debug for BoundedX509CertificateChain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedX509CertificateChain")
            .field("certificate_count", &self.certificates_der.len())
            .field("certificates_der", &"<redacted>")
            .finish()
    }
}

impl Zeroize for BoundedX509CertificateChain {
    fn zeroize(&mut self) {
        self.certificates_der.zeroize();
    }
}

impl Drop for BoundedX509CertificateChain {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BoundedX509CertificateChain {}

/// Trusted result returned by the host's Request Object certificate evaluator.
///
/// This is input to the Request Object pipeline, not the final receipt. The
/// pipeline binds it to the exact `x5c` header and JWS verification key before
/// constructing [`VerifiedX509CertificateBinding`].
///
/// The host evaluator must derive `leaf_public_key` and `dns_sans` from the
/// exact first DER certificate in `chain` after its selected path/profile
/// validation. `leaf_public_key` is the canonical verification-key encoding
/// supplied to JOSE; it need not preserve the certificate's SEC1 point form.
/// RFC 7515 Section 4.1.6 defines that first `x5c` entry as the certificate
/// containing the JWS signing key. Keeping this extraction in the injected
/// certificate evaluator avoids a second, potentially divergent PKIX parser.
// These fields are intentionally opaque. In no-JOSE builds the host can still
// construct the typed decision, but only a JOSE pipeline is allowed to consume
// its raw signer material and mint the final certificate-binding receipt.
#[cfg_attr(not(feature = "jose"), allow(dead_code))]
pub struct TrustedX509RequestObjectSigner {
    chain: BoundedX509CertificateChain,
    leaf_public_key: SecretSlice<u8>,
    dns_sans: Zeroizing<Vec<CanonicalDnsName>>,
    context: X509TrustDecisionContext,
}

impl TrustedX509RequestObjectSigner {
    /// Construct a trusted signer result from host-validated certificate evidence.
    ///
    /// DNS SANs are canonicalized at this trust boundary according to RFC 8399
    /// Section 2.3, rather than being retained as unchecked strings.
    pub fn new(
        chain: BoundedX509CertificateChain,
        mut leaf_public_key: Vec<u8>,
        mut dns_sans: Vec<String>,
        context: X509TrustDecisionContext,
    ) -> Result<Self, WalletError> {
        if leaf_public_key.is_empty()
            || leaf_public_key.len() > MAX_X509_LEAF_PUBLIC_KEY_BYTES
            || dns_sans.len() > MAX_X509_DNS_SAN_NAMES
        {
            leaf_public_key.zeroize();
            dns_sans.zeroize();
            return Err(WalletError::new(
                WalletErrorReason::MalformedX509CertificateChain,
            ));
        }
        let leaf_public_key: SecretSlice<u8> = leaf_public_key.into();
        let dns_sans = Zeroizing::new(dns_sans);
        let mut canonical_dns_sans = Zeroizing::new(Vec::with_capacity(dns_sans.len()));
        let mut total_dns_san_bytes = 0_usize;
        for dns_san in dns_sans.iter() {
            total_dns_san_bytes =
                total_dns_san_bytes
                    .checked_add(dns_san.len())
                    .ok_or_else(|| {
                        WalletError::new(WalletErrorReason::MalformedX509CertificateChain)
                    })?;
            if dns_san.len() > MAX_DNS_NAME_BYTES || total_dns_san_bytes > MAX_X509_DNS_SAN_BYTES {
                return Err(WalletError::new(
                    WalletErrorReason::MalformedX509CertificateChain,
                ));
            }
            canonical_dns_sans.push(
                CanonicalDnsName::parse_rfc5280_san(dns_san).map_err(|_| {
                    WalletError::new(WalletErrorReason::MalformedX509CertificateChain)
                })?,
            );
        }
        Ok(Self {
            chain,
            leaf_public_key,
            dns_sans: canonical_dns_sans,
            context,
        })
    }
}

impl fmt::Debug for TrustedX509RequestObjectSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedX509RequestObjectSigner(<redacted>)")
    }
}

impl ZeroizeOnDrop for TrustedX509RequestObjectSigner {}

/// Definitive or indeterminate X.509 trust result from the host evaluator.
#[derive(Debug)]
pub enum X509RequestObjectTrustDecision {
    /// The chain was accepted for the deployment-selected Request Object purpose.
    Trusted(TrustedX509RequestObjectSigner),
    /// The chain or certificate profile was definitively rejected.
    Rejected(X509TrustRejectionReason),
    /// Trust could not safely be established or rejected.
    Indeterminate(X509TrustIndeterminateReason),
}

/// Fixed reasons for definitive X.509 rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509TrustRejectionReason {
    /// PKIX path building or validation rejected every bounded candidate.
    PathRejected,
    /// Certificate or signature algorithm is outside policy.
    UnsupportedAlgorithm,
    /// The leaf or an applicable intermediate is revoked.
    Revoked,
    /// The certificate violates the selected deployment profile.
    ProfileViolation,
}

/// Fixed reasons for indeterminate X.509 trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509TrustIndeterminateReason {
    /// Trust-list, path, or status infrastructure is unavailable.
    EvidenceUnavailable,
    /// Cached trust or status evidence is stale.
    EvidenceStale,
    /// Status could not be established under policy.
    StatusUnknown,
}

/// Opaque signer-bound receipt created only by the Request Object pipeline.
pub struct VerifiedX509CertificateBinding {
    dns_names: Vec<CanonicalDnsName>,
    leaf_certificate_sha256: [u8; 32],
    chain_certificate_sha256: Vec<[u8; 32]>,
    context: X509TrustDecisionContext,
}

impl VerifiedX509CertificateBinding {
    #[cfg_attr(not(feature = "jose"), allow(dead_code))]
    pub(crate) fn from_trust_decision(
        decision: X509RequestObjectTrustDecision,
        jws_verification_key: &[u8],
        now_unix: u64,
    ) -> Result<Self, WalletError> {
        let mut signer = match decision {
            X509RequestObjectTrustDecision::Trusted(signer) => signer,
            X509RequestObjectTrustDecision::Rejected(reason) => {
                let mapped = match reason {
                    X509TrustRejectionReason::UnsupportedAlgorithm => {
                        WalletErrorReason::UnsupportedX509CertificateAlgorithm
                    }
                    X509TrustRejectionReason::PathRejected
                    | X509TrustRejectionReason::Revoked
                    | X509TrustRejectionReason::ProfileViolation => {
                        WalletErrorReason::X509CertificatePathRejected
                    }
                };
                return Err(WalletError::new(mapped));
            }
            X509RequestObjectTrustDecision::Indeterminate(reason) => {
                let mapped = match reason {
                    X509TrustIndeterminateReason::EvidenceStale => {
                        WalletErrorReason::X509TrustEvidenceStale
                    }
                    X509TrustIndeterminateReason::EvidenceUnavailable
                    | X509TrustIndeterminateReason::StatusUnknown => {
                        WalletErrorReason::X509TrustEvidenceUnavailable
                    }
                };
                return Err(WalletError::new(mapped));
            }
        };
        if !signer.context.is_fresh_at(now_unix) {
            return Err(WalletError::new(WalletErrorReason::X509TrustEvidenceStale));
        }
        if jws_verification_key.is_empty()
            || !constant_time_bytes_eq(signer.leaf_public_key.expose_secret(), jws_verification_key)
        {
            return Err(WalletError::new(WalletErrorReason::X509LeafKeyMismatch));
        }
        let dns_names = core::mem::take(&mut *signer.dns_sans);
        let leaf_certificate_sha256 = sha256_array(signer.chain.leaf_der());
        let chain_certificate_sha256 = signer.chain.fingerprints_sha256();
        Ok(Self {
            dns_names,
            leaf_certificate_sha256,
            chain_certificate_sha256,
            context: signer.context,
        })
    }

    #[cfg_attr(not(feature = "jose"), allow(dead_code))]
    pub(crate) fn matches_chain(&self, chain: &BoundedX509CertificateChain) -> bool {
        let actual = Zeroizing::new(chain.fingerprints_sha256());
        if actual.len() != self.chain_certificate_sha256.len() {
            return false;
        }
        actual
            .iter()
            .zip(&self.chain_certificate_sha256)
            .all(|(left, right)| constant_time_bytes_eq(left, right))
    }

    /// Return the exact SHA-256 identity of the request-signing leaf certificate.
    #[must_use]
    pub const fn leaf_certificate_sha256(&self) -> &[u8; 32] {
        &self.leaf_certificate_sha256
    }

    /// Return leaf-first SHA-256 identities for the bounded validated chain.
    #[must_use]
    pub fn chain_certificate_sha256(&self) -> &[[u8; 32]] {
        &self.chain_certificate_sha256
    }

    /// Return the accepted trust-purpose and provenance context.
    #[must_use]
    pub const fn trust_context(&self) -> &X509TrustDecisionContext {
        &self.context
    }

    pub(crate) fn contains_dns_name(&self, name: &CanonicalDnsName) -> bool {
        self.dns_names.iter().any(|candidate| candidate == name)
    }

    pub(crate) fn hash_matches(&self, encoded_hash: &str) -> bool {
        // OpenID4VP 1.0 Final Section 5.9.3 defines this as unpadded
        // base64url(SHA-256(DER leaf)); no textual certificate form is valid.
        let expected = Zeroizing::new(reallyme_codec::base64url::bytes_to_base64url(
            &self.leaf_certificate_sha256,
        ));
        constant_time_bytes_eq(expected.as_bytes(), encoded_hash.as_bytes())
    }
}

impl fmt::Debug for VerifiedX509CertificateBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedX509CertificateBinding")
            .field("dns_name_count", &self.dns_names.len())
            .field("certificate_count", &self.chain_certificate_sha256.len())
            .field("evidence", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedX509CertificateBinding {
    fn zeroize(&mut self) {
        self.dns_names.zeroize();
        self.leaf_certificate_sha256.zeroize();
        self.chain_certificate_sha256.zeroize();
        self.context.zeroize();
    }
}

impl Drop for VerifiedX509CertificateBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedX509CertificateBinding {}

#[cfg_attr(not(feature = "jose"), allow(dead_code))]
fn sha256_array(value: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(value);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

#[cfg(test)]
#[path = "validate_endpoint_binding_tests.rs"]
mod tests;
