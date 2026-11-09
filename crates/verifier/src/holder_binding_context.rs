// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_dcql::CredentialQuery;
use reallyme_openid4vp_types::PresentationValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{HolderBindingClaims, SessionRecord, VerifiedDisclosureSet, VerifierError};

/// Audited trust path used for one accepted presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedTrustProvenance {
    /// Issuer key came from authenticated deployment trust resolution.
    ResolvedIssuerKey,
    /// Issuer key was bound to a fully authenticated X.509 path.
    AuthenticatedX509,
    /// ISO mdoc issuer certificate path and MSO were authenticated.
    MdocIssuerCertificate,
    /// A configured proof verifier authenticated a derived-claim proof.
    VerifiedDerivedProof,
}

/// Complete format-verifier output retained for authorization persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedHolderBinding {
    claims: HolderBindingClaims,
    disclosures: VerifiedDisclosureSet,
    trust_provenance: VerifiedTrustProvenance,
}

impl VerifiedHolderBinding {
    /// Construct output at the trusted format-verifier boundary.
    #[must_use]
    pub const fn new(
        claims: HolderBindingClaims,
        disclosures: VerifiedDisclosureSet,
        trust_provenance: VerifiedTrustProvenance,
    ) -> Self {
        Self {
            claims,
            disclosures,
            trust_provenance,
        }
    }

    /// Borrow session-binding claims authenticated by the holder proof.
    #[must_use]
    pub const fn claims(&self) -> &HolderBindingClaims {
        &self.claims
    }

    /// Borrow the format verifier's immutable disclosure projection.
    #[must_use]
    pub const fn disclosures(&self) -> &VerifiedDisclosureSet {
        &self.disclosures
    }

    /// Return the authenticated issuer/proof trust path.
    #[must_use]
    pub const fn trust_provenance(&self) -> VerifiedTrustProvenance {
        self.trust_provenance
    }
}

impl fmt::Debug for VerifiedHolderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedHolderBinding")
            .field("trust_provenance", &self.trust_provenance)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedHolderBinding {
    fn zeroize(&mut self) {
        self.claims.zeroize();
        self.disclosures.zeroize();
    }
}

impl Drop for VerifiedHolderBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedHolderBinding {}

/// Active verifier-session context for format-specific holder verification.
///
/// Holder proof verification cannot be correct from presentation bytes alone.
/// SD-JWT VC needs the expected audience, nonce, and verification time, while
/// mdoc also needs session material derived from the same authorization flow.
/// Carrying the complete session here keeps those values bound to the
/// one-time session consumed by the HTTP runtime and avoids a second,
/// potentially divergent lookup inside a format adapter.
#[derive(Clone, Copy)]
pub struct HolderBindingVerificationContext<'a> {
    session: &'a SessionRecord,
    credential_query: &'a CredentialQuery,
    now_unix: u64,
}

impl<'a> HolderBindingVerificationContext<'a> {
    /// Construct context from the one-time verifier session and current time.
    #[must_use]
    pub const fn new(
        session: &'a SessionRecord,
        credential_query: &'a CredentialQuery,
        now_unix: u64,
    ) -> Self {
        Self {
            session,
            credential_query,
            now_unix,
        }
    }

    /// Session whose request binding the presentation must satisfy.
    #[must_use]
    pub const fn session(self) -> &'a SessionRecord {
        self.session
    }

    /// Validated DCQL credential query associated with this presentation.
    #[must_use]
    pub const fn credential_query(self) -> &'a CredentialQuery {
        self.credential_query
    }

    /// Current Unix time used for format-level proof freshness checks.
    #[must_use]
    pub const fn now_unix(self) -> u64 {
        self.now_unix
    }
}

impl fmt::Debug for HolderBindingVerificationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderBindingVerificationContext")
            .field("now_unix", &self.now_unix)
            .field("credential_format", &self.credential_query.format)
            .field("session", &"<redacted>")
            .finish()
    }
}

/// Host-injected verifier for presentation-format holder binding.
///
/// This is a security boundary, not a parsing extension point. Implementors
/// MUST return claims only after completing the format's cryptographic holder
/// authentication:
///
/// - For SD-JWT VC, RFC 9901 §§3.3, 4.1.2, 4.3, and 7.3 require the KB-JWT
///   when the issuer-signed `cnf` or verifier policy requires key binding, a
///   signature made by that exact confirmation key, and validation of `iat`,
///   `aud`, `nonce`, and `sd_hash`.
/// - For mdoc, OpenID4VP Appendix B.2.6 and ISO/IEC 18013-5 §9.1.3.5 require
///   DeviceAuth verification with the MSO device key over the exact session
///   transcript, document type, and device namespaces.
/// - For a typed ZK presentation, the implementation must verify every stage
///   against the claimed proof suite, circuit reference, artifact manifest,
///   and exact envelope binding. It must also establish issuer trust, current
///   credential status, and the projection from verified statements to the
///   supplied DCQL credential query. A backend success bit alone is not an
///   authorization decision.
/// - When an SD-JWT VC `status.status_list` claim or an mdoc MSO status or
///   identifier-list element is present, the referenced status artifact must
///   be fetched with bounded I/O, authenticated to the applicable credential
///   trust anchor, checked for type and index consistency, and enforced before
///   success is returned. Revocation maps to
///   [`crate::VerifierErrorReason::CredentialRevoked`]; malformed, untrusted, or
///   inconsistent status data maps to
///   [`crate::VerifierErrorReason::InvalidCredentialStatus`].
/// - A credential with no status information is valid at the protocol layer.
///   A deployment that requires status information may reject it through its
///   explicit trust policy using
///   [`crate::VerifierErrorReason::CredentialStatusUnavailable`].
///
/// Composed format adapters authenticate the credential, including its proof
/// and any applicable status evidence. This boundary accepts only their fully
/// verified output and then binds its decoded claims to the active OpenID4VP
/// session. Returning claims after issuer proof validation alone would
/// reintroduce replay or self-issued-credential acceptance.
pub trait HolderBindingVerifier: Send + Sync {
    /// Cryptographically verify the holder proof and return decoded claims.
    fn verify_holder_binding(
        &self,
        presentation: &PresentationValue,
        context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError>;
}
