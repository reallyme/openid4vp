// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use thiserror::Error;

/// Runtime service error with deterministic, non-PII reasons.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("OpenID4VP runtime error: {reason:?}")]
pub struct RuntimeError {
    reason: RuntimeErrorReason,
}

impl RuntimeError {
    /// Construct a runtime error from a stable reason.
    pub const fn new(reason: RuntimeErrorReason) -> Self {
        Self { reason }
    }

    /// Stable reason suitable for API and FFI mapping.
    pub const fn reason(self) -> RuntimeErrorReason {
        self.reason
    }
}

/// Stable runtime error taxonomy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeErrorReason {
    /// The protobuf request omitted a required field.
    MissingField,
    /// A protobuf/domain mapping failed.
    InvalidProto,
    /// The request asks for signing but no signer is configured.
    MissingSigner,
    /// The request uses a valid feature this runtime instance does not support.
    UnsupportedFeature,
    /// Request Object signing failed.
    SigningFailed,
    /// No decryptor is configured for encrypted Authorization Responses.
    MissingResponseJwtDecryptor,
    /// Encrypted Authorization Response compact serialization is malformed.
    InvalidResponseJwt,
    /// Encrypted Authorization Response decryption failed.
    ResponseJwtDecryptionFailed,
    /// Runtime clock could not provide a trusted timestamp.
    ClockUnavailable,
    /// Hosted Request Object could not be loaded.
    RequestObjectNotFound,
    /// Authorization Response validation failed.
    ResponseValidationFailed,
    /// No durable store is configured for a successfully verified response.
    MissingVerifiedResponseStore,
    /// Durable verified-response storage failed.
    VerifiedResponseStoreFailed,
    /// The host returned a malformed or insufficiently long response code.
    InvalidResponseCode,
    /// A validated session could not be consumed atomically.
    SessionConsumeFailed,
    /// No verifier session exists for the supplied private lookup key.
    SessionNotFound,
    /// The verifier session already has a durably committed outcome.
    SessionAlreadyConsumed,
    /// Another worker currently holds the exclusive session reservation.
    SessionReservationConflict,
    /// A failed response attempt could not release its session reservation.
    SessionReleaseFailed,
    /// The atomic session/result commit failed without changing durable state.
    SessionCommitFailed,
    /// HTTP method is not allowed for this endpoint.
    InvalidHttpMethod,
    /// HTTP content type is missing or unsupported.
    InvalidContentType,
    /// HTTP Accept header does not allow the response media type.
    InvalidAcceptHeader,
    /// HTTP request body exceeded endpoint policy.
    BodyTooLarge,
    /// Form-urlencoded body is malformed.
    InvalidFormBody,
    /// Required form field is absent.
    MissingFormField,
    /// Form field appeared more than once where duplicates are unsafe.
    DuplicateFormField,
    /// Request URI POST wallet_nonce did not match the hosted request.
    WalletNonceMismatch,
    /// The verifier host failed to store launch material atomically.
    LaunchStoreFailed,
    /// The verifier launch response could not be encoded.
    LaunchEncodingFailed,
    /// Redirect and initiating browser-session follow-back policy are inconsistent.
    InvalidFollowBackRequirement,
    /// The follow-back used a browser session other than the initiating session.
    FollowBackSessionMismatch,
    /// The same-device follow-back deadline has elapsed.
    FollowBackExpired,
    /// The response code has already completed its one-time follow-back transition.
    FollowBackAlreadyRedeemed,
    /// Durable follow-back redemption failed without releasing the accepted result.
    FollowBackRedemptionFailed,
}
