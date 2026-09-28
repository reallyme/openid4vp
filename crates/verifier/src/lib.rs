// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verifier-side OpenID4VP request and response validation boundary.

mod binding;
mod compare_secret;
mod error;
mod holder_binding;
mod jar;
#[cfg(any(feature = "native", feature = "wasm"))]
mod mdoc_holder_binding;
mod request_object;
mod response;
#[cfg(any(feature = "native", feature = "wasm"))]
mod sd_jwt_holder_binding;
mod session;
mod validate_transaction_data_binding;
mod verify_holder_binding;

pub use binding::{
    validate_request_binding, RequestBinding, TransactionDataBinding,
    MAX_TRANSACTION_DATA_BINDINGS, MIN_SESSION_BINDING_BYTES,
};
pub use error::{VerifierError, VerifierErrorReason};
pub use holder_binding::{validate_holder_binding_claims, HolderBindingClaims};
pub use jar::{
    build_signed_request_object, validate_jar_claims, validate_jar_claims_for_signing, CompactJwt,
    JarPolicy, RequestObjectSigner, MAX_COMPACT_REQUEST_OBJECT_JWT_BYTES,
    REQUEST_OBJECT_MEDIA_TYPE,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use mdoc_holder_binding::{
    MdocHolderBindingVerifier, MdocSessionTranscriptProvider, MdocStatusDecision,
    MdocStatusVerifier, OpenId4VpHolderBindingVerifier, RetainedMdocSessionTranscriptProvider,
};
pub use request_object::{RequestObjectVerifier, VerifiedRequestObject};
pub use response::{
    diagnose_authorization_response, diagnose_authorization_response_with_options,
    NonAuthorizingResponseDiagnostics, ResponseValidationOptions, VerifiedPresentation,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use sd_jwt_holder_binding::SdJwtHolderBindingVerifier;
pub use session::{
    BrowserSessionBinding, FollowBackRequirement, PostResponseRedirectUri,
    RetainedMdocSessionTranscript, SessionRecord, SessionStore, BROWSER_SESSION_BINDING_BYTES,
    MAX_RETAINED_MDOC_SESSION_TRANSCRIPT_BYTES,
};
pub use verify_holder_binding::{
    HolderBindingVerificationContext, HolderBindingVerifier, VerifiedDisclosureSet,
    VerifiedHolderBinding, VerifiedJsonClaims, VerifiedTrustProvenance,
};
