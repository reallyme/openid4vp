// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_dcql::CredentialQuery;
use reallyme_openid4vp_formats::mdoc::VerifiedMdocClaim;
use reallyme_openid4vp_types::PresentationValue;
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{HolderBindingClaims, SessionRecord, VerifierError};

const MAX_VERIFIED_CLAIMS_JSON_BYTES: usize = 256 * 1024;
const MAX_VERIFIED_CLAIMS_DEPTH: usize = 64;

/// Immutable issuer-authenticated JSON claims retained without reparsing.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedJsonClaims {
    value: JsonValue,
}

impl VerifiedJsonClaims {
    /// Retain a format verifier's authenticated disclosure projection.
    pub fn from_authenticated(value: JsonValue) -> Result<Self, VerifierError> {
        let encoded = reallyme_openid4vp_types::canonical_presentation_json_bytes(&value)
            .map_err(|_| VerifierError::new(crate::VerifierErrorReason::InvalidBinding))?;
        if encoded.len() > MAX_VERIFIED_CLAIMS_JSON_BYTES
            || json_depth(&value, 0)? > MAX_VERIFIED_CLAIMS_DEPTH
        {
            return Err(VerifierError::new(
                crate::VerifierErrorReason::InvalidBinding,
            ));
        }
        Ok(Self { value })
    }

    /// Borrow the already-authenticated claim tree.
    #[must_use]
    pub const fn as_value(&self) -> &JsonValue {
        &self.value
    }
}

impl fmt::Debug for VerifiedJsonClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedJsonClaims(<redacted>)")
    }
}

impl Zeroize for VerifiedJsonClaims {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.value);
    }
}

impl Drop for VerifiedJsonClaims {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedJsonClaims {}

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
}

impl fmt::Debug for VerifiedDisclosureSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::SdJwt(_) => "SdJwt",
            Self::Mdoc(_) => "Mdoc",
            Self::Derived => "Derived",
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
        }
    }
}

impl Drop for VerifiedDisclosureSet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedDisclosureSet {}

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

fn json_depth(value: &JsonValue, depth: usize) -> Result<usize, VerifierError> {
    if depth > MAX_VERIFIED_CLAIMS_DEPTH {
        return Err(VerifierError::new(
            crate::VerifierErrorReason::InvalidBinding,
        ));
    }
    let next = depth
        .checked_add(1)
        .ok_or_else(|| VerifierError::new(crate::VerifierErrorReason::InvalidBinding))?;
    match value {
        JsonValue::Array(values) => values.iter().try_fold(depth, |maximum, value| {
            json_depth(value, next).map(|child| maximum.max(child))
        }),
        JsonValue::Object(values) => values.values().try_fold(depth, |maximum, value| {
            json_depth(value, next).map(|child| maximum.max(child))
        }),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {
            Ok(depth)
        }
    }
}

fn zeroize_json_value(value: &mut JsonValue) {
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => {}
        JsonValue::String(value) => value.zeroize(),
        JsonValue::Array(values) => {
            for value in values {
                zeroize_json_value(value);
            }
        }
        JsonValue::Object(values) => {
            for (mut key, mut value) in core::mem::take(values) {
                key.zeroize();
                zeroize_json_value(&mut value);
            }
        }
    }
    *value = JsonValue::Null;
}
