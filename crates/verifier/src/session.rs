// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_dcql::DcqlQuery;
use reallyme_openid4vp_types::{ResponseMode, ValidatedHttpsEndpoint};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RequestBinding, VerifierError};

/// Maximum canonical CBOR bytes retained for an mdoc SessionTranscript.
///
/// The OpenID4VP transcript contains two null device-engagement values plus a
/// fixed label and SHA-256 handover digest. The deliberately conservative cap
/// prevents corrupted persistence or adapter input from turning session load
/// into an unbounded allocation boundary.
pub const MAX_RETAINED_MDOC_SESSION_TRANSCRIPT_BYTES: usize = 256;
/// SHA-256 thumbprint length retained for mdoc handover reconstruction.
pub const MDOC_RESPONSE_KEY_THUMBPRINT_BYTES: usize = 32;
/// Fixed length of the verifier-created initiating browser-session binding.
pub const BROWSER_SESSION_BINDING_BYTES: usize = 32;

/// Opaque verifier-host receipt for the browser session that initiated a flow.
///
/// This value is never sent to the wallet. A same-device follow-back endpoint
/// compares the authenticated browser cookie/session receipt with this exact
/// value before an accepted authorization result becomes releasable.
#[derive(Clone, PartialEq, Eq)]
pub struct BrowserSessionBinding {
    value: [u8; BROWSER_SESSION_BINDING_BYTES],
}

impl BrowserSessionBinding {
    /// Construct a binding from host-generated unpredictable bytes.
    #[must_use]
    pub const fn new(value: [u8; BROWSER_SESSION_BINDING_BYTES]) -> Self {
        Self { value }
    }

    /// Borrow the fixed-size binding for constant-time adapter comparison.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BROWSER_SESSION_BINDING_BYTES] {
        &self.value
    }
}

impl fmt::Debug for BrowserSessionBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrowserSessionBinding(<redacted>)")
    }
}

impl Zeroize for BrowserSessionBinding {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for BrowserSessionBinding {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for BrowserSessionBinding {}

/// One-time same-device follow-back requirement retained with a session.
#[derive(Clone, PartialEq, Eq)]
pub struct FollowBackRequirement {
    browser_session: BrowserSessionBinding,
    expires_unix: u64,
}

impl FollowBackRequirement {
    /// Construct a bounded follow-back requirement.
    pub fn new(
        browser_session: BrowserSessionBinding,
        expires_unix: u64,
    ) -> Result<Self, VerifierError> {
        if expires_unix == 0 {
            return Err(VerifierError::new(
                crate::VerifierErrorReason::InvalidBinding,
            ));
        }
        Ok(Self {
            browser_session,
            expires_unix,
        })
    }

    /// Borrow the initiating browser-session receipt.
    #[must_use]
    pub const fn browser_session(&self) -> &BrowserSessionBinding {
        &self.browser_session
    }

    /// Return the absolute follow-back deadline.
    #[must_use]
    pub const fn expires_unix(&self) -> u64 {
        self.expires_unix
    }
}

impl fmt::Debug for FollowBackRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FollowBackRequirement")
            .field("expires_unix", &self.expires_unix)
            .field("browser_session", &"<redacted>")
            .finish()
    }
}

impl Zeroize for FollowBackRequirement {
    fn zeroize(&mut self) {
        self.browser_session.zeroize();
        self.expires_unix.zeroize();
    }
}

impl Drop for FollowBackRequirement {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FollowBackRequirement {}

/// Validated HTTPS destination returned after successful response processing.
///
/// HAIP uses this verifier-owned URI for the post-verification user journey.
/// It is deliberately distinct from the Authorization Request `redirect_uri`,
/// which is forbidden for the direct-post modes used by the HAIP profile.
#[derive(Clone, PartialEq, Eq)]
pub struct PostResponseRedirectUri {
    value: String,
}

impl PostResponseRedirectUri {
    /// Validate and retain an absolute HTTPS redirect destination.
    pub fn parse(value: String) -> Result<Self, VerifierError> {
        ValidatedHttpsEndpoint::parse(&value)
            .map_err(|_| VerifierError::new(crate::VerifierErrorReason::InvalidRequestUri))?;
        Ok(Self { value })
    }

    /// Borrow the validated wire value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for PostResponseRedirectUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PostResponseRedirectUri(<redacted>)")
    }
}

impl Zeroize for PostResponseRedirectUri {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for PostResponseRedirectUri {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for PostResponseRedirectUri {}

/// Exact canonical mdoc SessionTranscript retained with a verifier session.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedMdocSessionTranscript {
    bytes: Vec<u8>,
    response_key_thumbprint_sha256: Option<[u8; MDOC_RESPONSE_KEY_THUMBPRINT_BYTES]>,
}

impl RetainedMdocSessionTranscript {
    /// Validate and retain canonical SessionTranscript bytes without a response key.
    ///
    /// This constructor is valid only for handover profiles that did not bind a
    /// response-encryption key. Use [`Self::new_with_response_key_thumbprint`]
    /// when the request advertised such a key.
    pub fn new(bytes: Vec<u8>) -> Result<Self, VerifierError> {
        Self::new_with_response_key_thumbprint(bytes, None)
    }

    /// Validate and retain canonical bytes plus their response-key binding.
    pub fn new_with_response_key_thumbprint(
        bytes: Vec<u8>,
        response_key_thumbprint_sha256: Option<[u8; MDOC_RESPONSE_KEY_THUMBPRINT_BYTES]>,
    ) -> Result<Self, VerifierError> {
        if bytes.is_empty() || bytes.len() > MAX_RETAINED_MDOC_SESSION_TRANSCRIPT_BYTES {
            return Err(VerifierError::new(
                crate::VerifierErrorReason::InvalidBinding,
            ));
        }
        Ok(Self {
            bytes,
            response_key_thumbprint_sha256,
        })
    }

    /// Borrow the exact bytes committed when the authorization request launched.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow the response-key thumbprint used to construct this transcript.
    #[must_use]
    pub const fn response_key_thumbprint_sha256(
        &self,
    ) -> Option<&[u8; MDOC_RESPONSE_KEY_THUMBPRINT_BYTES]> {
        self.response_key_thumbprint_sha256.as_ref()
    }
}

impl fmt::Debug for RetainedMdocSessionTranscript {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedMdocSessionTranscript")
            .field("byte_len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl Zeroize for RetainedMdocSessionTranscript {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
        self.response_key_thumbprint_sha256.zeroize();
    }
}

impl Drop for RetainedMdocSessionTranscript {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for RetainedMdocSessionTranscript {}

/// Verifier session record retained between request creation and response validation.
#[derive(Clone, PartialEq)]
pub struct SessionRecord {
    /// Request binding material.
    pub binding: RequestBinding,
    /// OIDC state value, when used.
    pub state: Option<String>,
    /// DCQL query used to create the authorization request.
    pub dcql_query: DcqlQuery,
    /// Response mode negotiated in the signed Authorization Request.
    ///
    /// Retaining this value prevents a session created for an encrypted
    /// response from being replayed through a plaintext endpoint.
    pub response_mode: ResponseMode,
    /// Exact canonical mdoc SessionTranscript, when the request may select mdoc.
    pub mdoc_session_transcript: Option<RetainedMdocSessionTranscript>,
    /// Verifier-owned destination returned after successful direct-post processing.
    pub post_response_redirect_uri: Option<PostResponseRedirectUri>,
    /// Same-device browser session required before releasing an accepted result.
    pub follow_back_requirement: Option<FollowBackRequirement>,
}

impl fmt::Debug for SessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRecord")
            .field("binding", &self.binding)
            .field("has_state", &self.state.is_some())
            .field("response_mode", &self.response_mode)
            .field(
                "has_mdoc_session_transcript",
                &self.mdoc_session_transcript.is_some(),
            )
            .field(
                "has_post_response_redirect_uri",
                &self.post_response_redirect_uri.is_some(),
            )
            .field(
                "has_follow_back_requirement",
                &self.follow_back_requirement.is_some(),
            )
            .field("dcql_query", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SessionRecord {
    fn zeroize(&mut self) {
        self.binding.zeroize();
        self.state.zeroize();
        self.dcql_query.zeroize();
        self.mdoc_session_transcript.zeroize();
        self.post_response_redirect_uri.zeroize();
        self.follow_back_requirement.zeroize();
    }
}

impl Drop for SessionRecord {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionRecord {}

/// Storage boundary for verifier sessions.
pub trait SessionStore: Send + Sync {
    /// Load a verifier session by an adapter-defined lookup key.
    fn load(&self, key: &str) -> Result<SessionRecord, VerifierError>;
}
