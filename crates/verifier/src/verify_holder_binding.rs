// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_formats::mdoc::VerifiedMdocClaim;
use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::ZkClaimProofBundleKind,
    claim_bundle::ZkVerifiedClaimStatement,
    common_root::ZkCommonCredentialRootPersonaMode,
    keys::{ZkIssuerPublicKey, ZkPersonaPublicKey},
    persona_evidence::{
        ZkPersonaCredentialEvidenceHolderPublicKey, ZkPersonaCredentialEvidenceMode,
    },
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[path = "verify_holder_binding_json.rs"]
mod verified_json;

pub use verified_json::VerifiedJsonClaims;

/// One claim and relationship commitment authenticated by a complete ZK bundle.
///
/// Cloning is deliberate: runtime persistence copies verified results across
/// its reservation boundary. Every copy owns a zeroizing claim buffer and
/// clears the presentation-scoped commitments when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedZkClaim {
    bundle_kind: ZkClaimProofBundleKind,
    hash_strategy: ZkCredentialHashAlgorithm,
    issuer: ZkIssuerPublicKey,
    persona: Option<ZkPersonaPublicKey>,
    credential_binding: [u8; 32],
    session_link_commitment: [u8; 32],
    claim_name_hash: [u8; 32],
    claim_value: Zeroizing<Vec<u8>>,
}

impl VerifiedZkClaim {
    pub(crate) fn from_verified(
        profile: ZkClaimProofBundleKind,
        hash_strategy: ZkCredentialHashAlgorithm,
        statement: &ZkVerifiedClaimStatement,
    ) -> Self {
        Self {
            bundle_kind: profile,
            hash_strategy,
            issuer: statement.issuer(),
            persona: statement.persona(),
            credential_binding: statement.credential_binding(),
            session_link_commitment: statement.session_link_commitment(),
            claim_name_hash: statement.claim_name_hash(),
            claim_value: Zeroizing::new(statement.claim_value().to_vec()),
        }
    }

    /// Production proof profile that established this statement.
    #[must_use]
    pub const fn bundle_kind(&self) -> ZkClaimProofBundleKind {
        self.bundle_kind
    }

    /// Hash lane of the proof's circuit public-input commitments.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.hash_strategy
    }

    /// Establish the same presenting key within one compatible proof session.
    ///
    /// A true result relies on complete verification of both bundles and the
    /// collision resistance of the selected circuit hash. A false result is
    /// inconclusive: a changed transaction digest or expiry also changes the
    /// session commitment. Private-claim proofs bind the credential subject
    /// key; persona profiles bind the persona key. This does not prove two
    /// credentials were issued to one natural person.
    #[must_use]
    pub fn same_presenting_key_in_session(&self, other: &Self) -> bool {
        self.bundle_kind == other.bundle_kind
            && self.hash_strategy == other.hash_strategy
            && bool::from(
                self.session_link_commitment
                    .ct_eq(&other.session_link_commitment),
            )
    }

    /// Issuer key admitted by the verifier's trust policy.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.issuer
    }

    /// Intentionally public persona key, when the profile exposes one.
    #[must_use]
    pub const fn persona(&self) -> Option<ZkPersonaPublicKey> {
        self.persona
    }

    /// Presentation-scoped commitment for same-credential composition.
    #[must_use]
    pub const fn credential_binding(&self) -> &[u8; 32] {
        &self.credential_binding
    }

    /// Presentation-scoped commitment for persona or subject continuity.
    #[must_use]
    pub const fn session_link_commitment(&self) -> &[u8; 32] {
        &self.session_link_commitment
    }

    /// Authenticated claim-name hash in the issuer's agreed schema.
    #[must_use]
    pub const fn claim_name_hash(&self) -> &[u8; 32] {
        &self.claim_name_hash
    }

    /// Authenticated disclosed claim bytes, without zero padding.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        &self.claim_value
    }
}

impl fmt::Debug for VerifiedZkClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkClaim")
            .field("profile", &self.bundle_kind)
            .field("hash_strategy", &self.hash_strategy)
            .field("issuer", &self.issuer)
            .field("persona", &self.persona)
            .field("claim_name_hash", &"<redacted>")
            .field("claim_value", &"<redacted>")
            .field("credential_binding", &"<redacted>")
            .field("session_link_commitment", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedZkClaim {
    fn zeroize(&mut self) {
        self.credential_binding.zeroize();
        self.session_link_commitment.zeroize();
        self.claim_name_hash.zeroize();
        self.claim_value.zeroize();
    }
}

impl Drop for VerifiedZkClaim {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedZkClaim {}

/// One selected claim authenticated by prepared evidence, current issuer
/// status, and a live holder signature over the exact verifier request.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedZkPersonaCredentialEvidenceClaim {
    mode: ZkPersonaCredentialEvidenceMode,
    hash_strategy: ZkCredentialHashAlgorithm,
    holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
    claim_name_hash: [u8; 32],
    claim_value: Zeroizing<Vec<u8>>,
}

impl VerifiedZkPersonaCredentialEvidenceClaim {
    pub(crate) fn from_verified(
        profile: ZkPersonaCredentialEvidenceMode,
        hash_strategy: ZkCredentialHashAlgorithm,
        holder_key: ZkPersonaCredentialEvidenceHolderPublicKey,
        claim_name_hash: [u8; 32],
        claim_value: &[u8],
    ) -> Self {
        Self {
            mode: profile,
            hash_strategy,
            holder_key,
            claim_name_hash,
            claim_value: Zeroizing::new(claim_value.to_vec()),
        }
    }

    /// Public or private one-time prepared profile.
    #[must_use]
    pub const fn mode(&self) -> ZkPersonaCredentialEvidenceMode {
        self.mode
    }

    /// Hash lane authenticated by the two prepared proofs.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.hash_strategy
    }

    /// Key whose live signature bound this result to the verifier request.
    #[must_use]
    pub const fn holder_key(&self) -> ZkPersonaCredentialEvidenceHolderPublicKey {
        self.holder_key
    }

    /// Exact issuer-credential claim name selected by verifier policy.
    #[must_use]
    pub const fn claim_name_hash(&self) -> &[u8; 32] {
        &self.claim_name_hash
    }

    /// Exact value established by the proof and required by policy.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        &self.claim_value
    }
}

impl fmt::Debug for VerifiedZkPersonaCredentialEvidenceClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkPersonaCredentialEvidenceClaim")
            .field("profile", &self.mode)
            .field("hash_strategy", &self.hash_strategy)
            .field("holder_key", &"<redacted>")
            .field("claim_name_hash", &"<redacted>")
            .field("claim_value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedZkPersonaCredentialEvidenceClaim {
    fn zeroize(&mut self) {
        self.holder_key.x.zeroize();
        self.holder_key.y.zeroize();
        self.claim_name_hash.zeroize();
        self.claim_value.zeroize();
    }
}

impl Drop for VerifiedZkPersonaCredentialEvidenceClaim {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedZkPersonaCredentialEvidenceClaim {}

#[cfg(test)]
#[path = "verify_holder_binding_zk_tests.rs"]
mod zk_composition_tests;

/// One claim authenticated inside a common-credential-root presentation.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedZkCommonCredentialRootClaim {
    issuer: ZkIssuerPublicKey,
    claim_name_hash: [u8; 32],
    claim_value: Zeroizing<Vec<u8>>,
}

impl VerifiedZkCommonCredentialRootClaim {
    pub(crate) fn from_verified(
        issuer: ZkIssuerPublicKey,
        claim_name_hash: [u8; 32],
        claim_value: &[u8],
    ) -> Self {
        Self {
            issuer,
            claim_name_hash,
            claim_value: Zeroizing::new(claim_value.to_vec()),
        }
    }

    /// Issuer key admitted by the verifier's policy for this role.
    #[must_use]
    pub const fn issuer(&self) -> ZkIssuerPublicKey {
        self.issuer
    }

    /// Authenticated requested claim-name hash.
    #[must_use]
    pub const fn claim_name_hash(&self) -> &[u8; 32] {
        &self.claim_name_hash
    }

    /// Authenticated disclosed claim bytes, without zero padding.
    #[must_use]
    pub fn claim_value(&self) -> &[u8] {
        &self.claim_value
    }
}

impl fmt::Debug for VerifiedZkCommonCredentialRootClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkCommonCredentialRootClaim")
            .field("issuer", &self.issuer)
            .field("claim_name_hash", &"<redacted>")
            .field("claim_value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedZkCommonCredentialRootClaim {
    fn zeroize(&mut self) {
        self.claim_name_hash.zeroize();
        self.claim_value.zeroize();
    }
}

impl Drop for VerifiedZkCommonCredentialRootClaim {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedZkCommonCredentialRootClaim {}

/// Complete common-credential-root result accepted by the injected proof verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedZkCommonCredentialRootPresentation {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    hash_strategy: ZkCredentialHashAlgorithm,
    verified_proof_count: u8,
    claims: [VerifiedZkCommonCredentialRootClaim; 2],
}

impl VerifiedZkCommonCredentialRootPresentation {
    pub(crate) const fn from_verified(
        profile: ZkCommonCredentialRootPersonaMode,
        hash_strategy: ZkCredentialHashAlgorithm,
        verified_proof_count: u8,
        claims: [VerifiedZkCommonCredentialRootClaim; 2],
    ) -> Self {
        Self {
            persona_mode: profile,
            hash_strategy,
            verified_proof_count,
            claims,
        }
    }

    /// Common-credential-root profile that established the composition.
    #[must_use]
    pub const fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    /// Hash lane used by every proof in the composition.
    #[must_use]
    pub const fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.hash_strategy
    }

    /// Number of proofs checked by the injected verifier.
    #[must_use]
    pub const fn verified_proof_count(&self) -> u8 {
        self.verified_proof_count
    }

    /// Ordered credential-role claims accepted by verifier policy.
    #[must_use]
    pub const fn claims(&self) -> &[VerifiedZkCommonCredentialRootClaim; 2] {
        &self.claims
    }
}

impl fmt::Debug for VerifiedZkCommonCredentialRootPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedZkCommonCredentialRootPresentation")
            .field("profile", &self.persona_mode)
            .field("hash_strategy", &self.hash_strategy)
            .field("verified_proof_count", &self.verified_proof_count)
            .field("claims", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedZkCommonCredentialRootPresentation {
    fn zeroize(&mut self) {
        self.verified_proof_count.zeroize();
        self.claims.zeroize();
    }
}

impl Drop for VerifiedZkCommonCredentialRootPresentation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedZkCommonCredentialRootPresentation {}

/// Format-specific disclosures that survived cryptographic verification.
#[derive(Clone, PartialEq, Eq)]
pub enum VerifiedDisclosureSet {
    /// SD-JWT disclosure-resolved JSON claims.
    SdJwt(VerifiedJsonClaims),
    /// Issuer-authenticated mdoc claim identifiers. Raw PID values remain
    /// inside the format verifier's protected envelope by design.
    Mdoc(Vec<VerifiedMdocClaim>),
    /// A proof establishes derived statements without releasing raw claims.
    Derived,
    /// Complete ZK bundle established this exact claim and its relationship commitments.
    ZkClaim(Box<VerifiedZkClaim>),
    /// Prepared claim with current status and live request authentication.
    ZkPersonaCredentialEvidence(Box<VerifiedZkPersonaCredentialEvidenceClaim>),
    /// Common-credential-root ZK presentation established two requested credential roles.
    ZkCommonCredentialRoot(Box<VerifiedZkCommonCredentialRootPresentation>),
}

impl fmt::Debug for VerifiedDisclosureSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::SdJwt(_) => "SdJwt",
            Self::Mdoc(_) => "Mdoc",
            Self::Derived => "Derived",
            Self::ZkClaim(_) => "ZkClaim",
            Self::ZkPersonaCredentialEvidence(_) => "ZkPersonaCredentialEvidence",
            Self::ZkCommonCredentialRoot(_) => "ZkCommonCredentialRoot",
        };
        formatter
            .debug_struct("VerifiedDisclosureSet")
            .field("variant", &variant)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedDisclosureSet {
    fn zeroize(&mut self) {
        match self {
            Self::SdJwt(claims) => claims.zeroize(),
            Self::Mdoc(claims) => claims.zeroize(),
            Self::Derived => {}
            Self::ZkClaim(claim) => claim.zeroize(),
            Self::ZkPersonaCredentialEvidence(claim) => claim.zeroize(),
            Self::ZkCommonCredentialRoot(presentation) => presentation.zeroize(),
        }
    }
}

impl Drop for VerifiedDisclosureSet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedDisclosureSet {}
