// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Statement proven by a derived ZK presentation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedClaimStatement {
    /// Stable statement identifier from policy or DCQL matching context.
    pub statement_id: String,
    /// Non-PII semantic label, for example `age_over_18`.
    pub statement: String,
}

impl fmt::Debug for DerivedClaimStatement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedClaimStatement")
            .field("statement_id", &"<redacted>")
            .field("statement", &"<redacted>")
            .finish()
    }
}

impl Zeroize for DerivedClaimStatement {
    fn zeroize(&mut self) {
        self.statement_id.zeroize();
        self.statement.zeroize();
    }
}

impl Drop for DerivedClaimStatement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DerivedClaimStatement {}

/// Binding hashes embedded in the ZK presentation envelope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentationBinding {
    /// SHA-256 hash of the active OpenID4VP nonce.
    pub nonce_hash: [u8; 32],
    /// SHA-256 hash of the verifier identity/audience.
    pub audience_hash: [u8; 32],
    /// SHA-256 hash of transaction data when present.
    pub transaction_data_hash: Option<[u8; 32]>,
}

impl fmt::Debug for ZkPresentationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZkPresentationBinding(<redacted>)")
    }
}

impl Zeroize for ZkPresentationBinding {
    fn zeroize(&mut self) {
        self.nonce_hash.zeroize();
        self.audience_hash.zeroize();
        self.transaction_data_hash.zeroize();
    }
}

impl Drop for ZkPresentationBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPresentationBinding {}

/// Exact imported circuit source used for an artifact-backed proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentationCircuitRef {
    /// Hash lane used by the concrete imported circuit.
    pub hash_strategy: String,
    /// VC circuit family.
    pub family: String,
    /// Stage within the circuit family.
    pub stage: String,
    /// Monotonic semantic circuit version.
    pub version: u32,
}

impl fmt::Debug for ZkPresentationCircuitRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkPresentationCircuitRef")
            .field("hash_strategy", &self.hash_strategy)
            .field("family", &self.family)
            .field("stage", &self.stage)
            .field("version", &self.version)
            .finish()
    }
}

impl Zeroize for ZkPresentationCircuitRef {
    fn zeroize(&mut self) {
        self.hash_strategy.zeroize();
        self.family.zeroize();
        self.stage.zeroize();
        self.version.zeroize();
    }
}

impl Drop for ZkPresentationCircuitRef {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPresentationCircuitRef {}

/// Fully specified proof suite carried by a ZK presentation envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkPresentationProofSuite {
    /// Approved production suite with a Keccak transcript and ZK masking.
    BarretenbergUltraHonkKeccakZkNoIpa,
}

/// Production credential-proof profile carried by a ZK presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkPresentationProfile {
    /// Private first-person claim proof.
    PrivateClaimV1,
    /// Private same-holder persona proof.
    PrivatePersonaClaimV1,
    /// Public, intentionally linkable persona proof.
    PublicPersonaClaimV1,
}

/// Required production stage carried in a ZK presentation bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkPresentationStageKind {
    /// Session challenge and holder authorization.
    Session,
    /// Issuer authentication of the credential envelope.
    CredentialEnvelope,
    /// Issuer authentication of the envelope-to-claim-root binding.
    CredentialRoot,
    /// Holder-bound claim membership proof.
    Claim,
}

/// One exact circuit proof inside the production presentation bundle.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentationStage {
    /// Stable production stage identity.
    pub stage: ZkPresentationStageKind,
    /// Exact imported circuit source and semantic version.
    pub circuit_ref: ZkPresentationCircuitRef,
    /// SHA-256 identity of the canonical artifact manifest.
    pub artifact_manifest_sha256: [u8; 32],
    /// Opaque proof bytes owned by the injected backend.
    pub proof: Vec<u8>,
    /// Serialized public inputs for this exact stage ABI.
    pub public_inputs: Vec<u8>,
}

impl fmt::Debug for ZkPresentationStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkPresentationStage")
            .field("stage", &self.stage)
            .field("circuit_ref", &self.circuit_ref)
            .field("artifact_manifest_sha256", &"<redacted>")
            .field("proof_len", &self.proof.len())
            .field("proof", &"<redacted>")
            .field("public_inputs_len", &self.public_inputs.len())
            .field("public_inputs", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ZkPresentationStage {
    fn zeroize(&mut self) {
        self.circuit_ref.zeroize();
        self.artifact_manifest_sha256.zeroize();
        self.proof.zeroize();
        self.public_inputs.zeroize();
    }
}

impl Drop for ZkPresentationStage {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPresentationStage {}

/// JSON-native ZK `vp_token` presentation entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPresentation {
    /// Format marker for fail-closed detection.
    #[serde(rename = "type")]
    pub type_: String,
    /// Production credential-proof profile shared by every stage.
    pub profile: ZkPresentationProfile,
    /// Exact proof-system suite claimed by the presentation.
    pub proof_suite: ZkPresentationProofSuite,
    /// Complete four-stage production proof bundle.
    pub stages: Vec<ZkPresentationStage>,
    /// Derived claims asserted by this proof.
    pub derived_claims: Vec<DerivedClaimStatement>,
    /// Session binding hashes duplicated for format-layer checking.
    pub binding: ZkPresentationBinding,
}

impl fmt::Debug for ZkPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ZkPresentation")
            .field("type", &self.type_)
            .field("profile", &self.profile)
            .field("proof_suite", &self.proof_suite)
            .field("stage_count", &self.stages.len())
            .field("stages", &"<redacted>")
            .field("derived_claim_count", &self.derived_claims.len())
            .field("binding", &"<redacted>")
            .finish()
    }
}

impl Zeroize for ZkPresentation {
    fn zeroize(&mut self) {
        self.type_.zeroize();
        self.stages.zeroize();
        self.derived_claims.zeroize();
        self.binding.zeroize();
    }
}

impl Drop for ZkPresentation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ZkPresentation {}
