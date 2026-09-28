// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP bindings for the W3C Digital Credentials API and ISO 18013-7 Annex B.
//!
//! The W3C Digital Credentials API is an Editor's Draft, so wire details here
//! are deliberately small, typed, and isolated behind this crate. OpenID4VP
//! profile and transport crates should depend on these models rather than
//! duplicating draft-specific strings.
//!
//! Serde implementations in this crate exist only for bounded internal
//! protocol parsing. They are not stable SDK DTO contracts. Cross-language and
//! SDK boundaries must use the generated OpenID4VP protobuf messages and
//! generated ProtoJSON.

mod error;
mod mdoc;
mod request;
mod request_deserialize;
mod response;

pub use error::{DcApiError, DcApiErrorReason};
pub use mdoc::{
    build_dc_api_handover_digest, build_dc_api_session_transcript, build_redirect_handover_digest,
    build_redirect_session_transcript, CanonicalMdocHandoverCborEncoder, EncodedHandoverInfo,
    EncodedMdocSessionTranscript, HandoverDigest, HandoverDigestInput, HandoverKind,
    MdocDeviceResponseB64, MdocHandoverCborEncoder, OpenId4VpDcApiHandover,
    OpenId4VpRedirectHandover, MAX_MDOC_HANDOVER_TEXT_BYTES, SHA256_DIGEST_BYTES,
};
pub use request::{
    DcApiProtocol, DcApiRequestKind, DigitalCredentialGetRequest, DigitalCredentialGetRequestData,
    DigitalCredentialRequestOptions, JwsJsonGeneral, JwsJsonSignature, MAX_JWS_JSON_GENERAL_BYTES,
    MAX_JWS_JSON_SIGNATURES, OPENID4VP_PROTOCOL_PREFIX,
};
pub use response::{DcApiAuthorizationResponse, EncryptedDcApiAuthorizationResponse};
