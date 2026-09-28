// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::record_verifier_evidence::VerifierEvidenceOutcome;

/// HTTP method understood by the runtime endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
}

/// Framework-neutral HTTP request projection.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeHttpRequest {
    /// Request method.
    pub method: RuntimeHttpMethod,
    /// Raw Accept header, when present.
    pub accept: Option<String>,
    /// Raw Content-Type header, when present.
    pub content_type: Option<String>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

impl fmt::Debug for RuntimeHttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeHttpRequest")
            .field("method", &self.method)
            .field("accept", &self.accept)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

impl Zeroize for RuntimeHttpRequest {
    fn zeroize(&mut self) {
        self.accept.zeroize();
        self.content_type.zeroize();
        self.body.zeroize();
    }
}

impl Drop for RuntimeHttpRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RuntimeHttpRequest {}

/// Framework-neutral HTTP response projection.
#[derive(Clone, PartialEq, Eq)]
pub struct RuntimeHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response Content-Type.
    pub content_type: Option<&'static str>,
    /// Cache-Control header.
    pub cache_control: Option<&'static str>,
    /// Response body bytes.
    pub body: Vec<u8>,
    /// Protocol disposition is deliberately independent from HTTP status:
    /// OAuth error acknowledgements are 2xx responses but are not acceptance.
    pub(crate) evidence_outcome: VerifierEvidenceOutcome,
}

impl fmt::Debug for RuntimeHttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeHttpResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("cache_control", &self.cache_control)
            .field("body_len", &self.body.len())
            .field("body", &"<redacted>")
            .finish()
    }
}

impl Zeroize for RuntimeHttpResponse {
    fn zeroize(&mut self) {
        self.body.zeroize();
        self.content_type = None;
        self.cache_control = None;
    }
}

impl Drop for RuntimeHttpResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RuntimeHttpResponse {}

impl RuntimeHttpResponse {
    /// Build an empty response.
    pub const fn empty(status: u16) -> Self {
        Self {
            status,
            content_type: None,
            cache_control: None,
            body: Vec::new(),
            evidence_outcome: VerifierEvidenceOutcome::Rejected,
        }
    }

    /// Build a response with body and content type.
    pub fn with_body(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: Some(content_type),
            cache_control: None,
            body,
            evidence_outcome: VerifierEvidenceOutcome::Rejected,
        }
    }

    /// Attach a Cache-Control header value.
    #[must_use]
    pub const fn with_cache_control(mut self, value: &'static str) -> Self {
        self.cache_control = Some(value);
        self
    }

    /// Mark a response as the result of a completed protocol acceptance.
    #[must_use]
    pub(crate) const fn accepted(mut self) -> Self {
        self.evidence_outcome = VerifierEvidenceOutcome::Accepted;
        self
    }
}
