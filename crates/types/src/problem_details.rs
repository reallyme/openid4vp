// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};

/// RFC 9457 media type for JSON problem details.
pub const PROBLEM_JSON_MEDIA_TYPE: &str = "application/problem+json";

/// Stable OpenID4VP problem taxonomy for RFC 9457 mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProblemKind {
    /// The request is malformed or violates OpenID4VP final request rules.
    InvalidRequest,
    /// The signed Request Object is malformed, unverifiable, expired, or policy-invalid.
    InvalidRequestObject,
    /// Client identifier prefix binding failed.
    InvalidClientIdentifier,
    /// The DCQL query is malformed or unsupported.
    InvalidDcqlQuery,
    /// No wallet credential satisfies the DCQL query.
    UnsatisfiedDcqlQuery,
    /// Request or response binding has expired.
    BindingExpired,
    /// The verifier session cannot be found.
    SessionNotFound,
    /// The verifier session does not match the response.
    SessionMismatch,
    /// The requested feature is valid but unsupported by this implementation.
    UnsupportedFeature,
    /// The wallet cannot complete the requested operation.
    WalletUnavailable,
    /// Internal server error with no sensitive details exposed.
    Internal,
}

impl ProblemKind {
    /// Return the RFC 9457 HTTP status code for this problem class.
    pub const fn status_code(self) -> HttpStatusCode {
        match self {
            Self::InvalidRequest
            | Self::InvalidRequestObject
            | Self::InvalidClientIdentifier
            | Self::InvalidDcqlQuery
            | Self::BindingExpired
            | Self::SessionMismatch
            | Self::UnsupportedFeature => HttpStatusCode::BAD_REQUEST,
            Self::UnsatisfiedDcqlQuery | Self::WalletUnavailable => {
                HttpStatusCode::UNPROCESSABLE_CONTENT
            }
            Self::SessionNotFound => HttpStatusCode::NOT_FOUND,
            Self::Internal => HttpStatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Return the non-PII problem type URI for this problem class.
    pub const fn problem_type(self) -> ProblemType {
        match self {
            Self::InvalidRequest => ProblemType::new("https://really.me/problems/invalid-request"),
            Self::InvalidRequestObject => {
                ProblemType::new("https://really.me/problems/invalid-request-object")
            }
            Self::InvalidClientIdentifier => {
                ProblemType::new("https://really.me/problems/invalid-client-identifier")
            }
            Self::InvalidDcqlQuery => {
                ProblemType::new("https://really.me/problems/invalid-dcql-query")
            }
            Self::UnsatisfiedDcqlQuery => {
                ProblemType::new("https://really.me/problems/unsatisfied-dcql-query")
            }
            Self::BindingExpired => ProblemType::new("https://really.me/problems/binding-expired"),
            Self::SessionNotFound => {
                ProblemType::new("https://really.me/problems/session-not-found")
            }
            Self::SessionMismatch => {
                ProblemType::new("https://really.me/problems/session-mismatch")
            }
            Self::UnsupportedFeature => {
                ProblemType::new("https://really.me/problems/unsupported-feature")
            }
            Self::WalletUnavailable => {
                ProblemType::new("https://really.me/problems/wallet-unavailable")
            }
            Self::Internal => ProblemType::new("https://really.me/problems/internal"),
        }
    }

    /// Return a stable, non-PII problem title.
    pub const fn title(self) -> ProblemTitle {
        match self {
            Self::InvalidRequest => ProblemTitle::new("Invalid request"),
            Self::InvalidRequestObject => ProblemTitle::new("Invalid request object"),
            Self::InvalidClientIdentifier => ProblemTitle::new("Invalid client identifier"),
            Self::InvalidDcqlQuery => ProblemTitle::new("Invalid DCQL query"),
            Self::UnsatisfiedDcqlQuery => ProblemTitle::new("Unsatisfied DCQL query"),
            Self::BindingExpired => ProblemTitle::new("Binding expired"),
            Self::SessionNotFound => ProblemTitle::new("Session not found"),
            Self::SessionMismatch => ProblemTitle::new("Session mismatch"),
            Self::UnsupportedFeature => ProblemTitle::new("Unsupported feature"),
            Self::WalletUnavailable => ProblemTitle::new("Wallet unavailable"),
            Self::Internal => ProblemTitle::new("Internal server error"),
        }
    }
}

/// HTTP status code used in RFC 9457 problem details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HttpStatusCode(u16);

impl HttpStatusCode {
    /// HTTP 400.
    pub const BAD_REQUEST: Self = Self(400);
    /// HTTP 404.
    pub const NOT_FOUND: Self = Self(404);
    /// HTTP 422.
    pub const UNPROCESSABLE_CONTENT: Self = Self(422);
    /// HTTP 500.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);

    /// Return the numeric status code.
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

/// RFC 9457 problem type URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProblemType(&'static str);

impl ProblemType {
    /// Construct a static problem type URI.
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Return the problem type URI.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// RFC 9457 problem title.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProblemTitle(&'static str);

impl ProblemTitle {
    /// Construct a static problem title.
    pub const fn new(value: &'static str) -> Self {
        Self(value)
    }

    /// Return the problem title.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// RFC 9457 problem instance URI.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProblemInstance(String);

impl fmt::Debug for ProblemInstance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProblemInstance(<redacted>)")
    }
}

impl ProblemInstance {
    /// Construct a problem instance URI supplied by the transport adapter.
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Return the problem instance URI.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Extension member carrying the stable protocol error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProblemDetailsExt {
    /// Deterministic OpenID4VP problem kind.
    pub kind: ProblemKind,
}

/// RFC 9457 Problem Details object.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ProblemDetails {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub problem_type: ProblemType,
    /// Short, stable summary.
    pub title: ProblemTitle,
    /// HTTP status code generated by the origin server.
    pub status: HttpStatusCode,
    /// Instance URI for correlation, supplied by the transport adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<ProblemInstance>,
    /// Extension members. Kept structured to avoid leaking request contents in strings.
    #[serde(flatten)]
    pub extensions: ProblemDetailsExt,
}

impl fmt::Debug for ProblemDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProblemDetails")
            .field("problem_type", &self.problem_type)
            .field("title", &self.title)
            .field("status", &self.status)
            .field("has_instance", &self.instance.is_some())
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl ProblemDetails {
    /// Construct a problem details object from the stable OpenID4VP taxonomy.
    pub const fn from_kind(kind: ProblemKind) -> Self {
        Self {
            problem_type: kind.problem_type(),
            title: kind.title(),
            status: kind.status_code(),
            instance: None,
            extensions: ProblemDetailsExt { kind },
        }
    }

    /// Attach a transport-owned problem instance URI.
    pub fn with_instance(mut self, instance: ProblemInstance) -> Self {
        self.instance = Some(instance);
        self
    }
}

impl From<OpenId4vpTypeError> for ProblemDetails {
    fn from(error: OpenId4vpTypeError) -> Self {
        let kind = match error.reason() {
            OpenId4vpTypeErrorReason::InvalidClientIdentifierPrefix => {
                ProblemKind::InvalidClientIdentifier
            }
            OpenId4vpTypeErrorReason::EmptyValue
            | OpenId4vpTypeErrorReason::EmptyCollection
            | OpenId4vpTypeErrorReason::InvalidEncoding
            | OpenId4vpTypeErrorReason::InvalidRequestObjectJwt
            | OpenId4vpTypeErrorReason::JsonDepthExceeded
            | OpenId4vpTypeErrorReason::JsonSizeExceeded
            | OpenId4vpTypeErrorReason::DuplicateJsonKey
            | OpenId4vpTypeErrorReason::SerializationFailed
            | OpenId4vpTypeErrorReason::UnsupportedMetadataCapability
            | OpenId4vpTypeErrorReason::UnsupportedTransactionDataHashAlgorithm
            | OpenId4vpTypeErrorReason::EmptyPresentationList => ProblemKind::InvalidRequest,
        };
        Self::from_kind(kind)
    }
}

#[cfg(test)]
#[path = "problem_details_tests.rs"]
mod tests;
