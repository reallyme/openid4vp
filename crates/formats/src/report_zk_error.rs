// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// ZK presentation format error.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP ZK presentation format error: {reason:?}")]
pub struct ZkFormatError {
    reason: ZkFormatErrorReason,
}

impl ZkFormatError {
    /// Build a ZK format error from a stable reason.
    pub const fn new(reason: ZkFormatErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for deterministic API and FFI mapping.
    pub const fn reason(self) -> ZkFormatErrorReason {
        self.reason
    }
}

/// Stable ZK presentation error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkFormatErrorReason {
    /// Circuit id is not registered.
    UnknownCircuit,
    /// Registered circuit is not supported by the active backend or policy.
    UnsupportedCircuit,
    /// Proof suite is known but is not approved for production verification.
    UnsupportedProofSuite,
    /// ZK presentation envelope, proof, or public inputs were malformed.
    InvalidPresentationEncoding,
    /// Proof verification failed.
    InvalidProof,
    /// Presentation binding does not match the active OpenID4VP session.
    BindingMismatch,
    /// Proof material does not belong to the supplied SSI credential issuance.
    CredentialBindingMismatch,
    /// Backend verifier/prover is unavailable or failed without safe details.
    VerifierUnavailable,
    /// Backend verified a different circuit than the presentation claimed.
    CircuitVerificationMismatch,
}
