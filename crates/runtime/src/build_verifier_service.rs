// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use reallyme_openid4vp_verifier::{HolderBindingVerifier, RequestObjectSigner};

use crate::AuthorizationResponseJwtDecryptor;

/// Runtime dependencies for transport-neutral verifier operations.
#[derive(Clone)]
pub struct VerifierRuntimeConfig {
    /// Optional signer for RFC 9101 Request Object responses.
    pub signer: Option<Arc<dyn RequestObjectSigner + Send + Sync>>,
    /// Optional decryptor for encrypted `direct_post.jwt` responses.
    pub response_jwt_decryptor: Option<Arc<dyn AuthorizationResponseJwtDecryptor>>,
    /// Optional full credential and holder-binding verifier.
    ///
    /// Implementations also enforce any referenced credential-status artifact
    /// before returning verified claims. Every presentation format, including
    /// a typed ZK envelope, fails closed when this dependency is absent.
    pub holder_binding_verifier: Option<Arc<dyn HolderBindingVerifier>>,
}

impl VerifierRuntimeConfig {
    /// Build a config with no optional crypto backends.
    pub fn new() -> Self {
        Self {
            signer: None,
            response_jwt_decryptor: None,
            holder_binding_verifier: None,
        }
    }

    /// Attach a Request Object signer.
    #[must_use]
    pub fn with_signer(mut self, signer: Arc<dyn RequestObjectSigner + Send + Sync>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach an encrypted Authorization Response decryptor.
    #[must_use]
    pub fn with_response_jwt_decryptor(
        mut self,
        decryptor: Arc<dyn AuthorizationResponseJwtDecryptor>,
    ) -> Self {
        self.response_jwt_decryptor = Some(decryptor);
        self
    }

    /// Attach a credential and holder-binding verifier for SD-JWT, mdoc, and
    /// other envelope formats.
    #[must_use]
    pub fn with_holder_binding_verifier(
        mut self,
        verifier: Arc<dyn HolderBindingVerifier>,
    ) -> Self {
        self.holder_binding_verifier = Some(verifier);
        self
    }
}

impl Default for VerifierRuntimeConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Transport-neutral verifier operation implementation backed by protocol crates.
pub struct VerifierRuntimeService {
    config: VerifierRuntimeConfig,
}

impl VerifierRuntimeService {
    /// Construct the runtime verifier service.
    pub fn new(config: VerifierRuntimeConfig) -> Self {
        Self { config }
    }

    pub(crate) fn signer(&self) -> Option<&(dyn RequestObjectSigner + Send + Sync)> {
        self.config.signer.as_deref()
    }

    pub(crate) fn response_jwt_decryptor(&self) -> Option<&dyn AuthorizationResponseJwtDecryptor> {
        self.config.response_jwt_decryptor.as_deref()
    }

    pub(crate) fn holder_binding_verifier(&self) -> Option<&dyn HolderBindingVerifier> {
        self.config.holder_binding_verifier.as_deref()
    }
}
