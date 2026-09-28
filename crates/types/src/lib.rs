// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenID4VP 1.0 final protocol types.
//!
//! Serde implementations in this crate exist only for bounded internal
//! protocol parsing. They are not stable SDK DTO contracts. Cross-language and
//! SDK boundaries must use the generated `reallyme-openid4vp-proto` messages
//! and `reallyme-openid4vp-proto-codec` ProtoJSON helpers.

mod classify_request_object_jwt;
mod client_id;
mod define_media_types;
mod define_metadata;
mod endpoint;
mod error;
mod problem_details;
mod request;
mod response;
mod transaction_data;
mod zeroize_json;

pub use classify_request_object_jwt::{classify_request_object_jwt, RequestObjectJwtKind};
pub use client_id::{ClientIdentifier, ClientIdentifierPrefix};
pub use define_media_types::{
    JSON_MEDIA_TYPE, REQUEST_OBJECT_MEDIA_TYPE, VERIFIER_ATTESTATION_MEDIA_TYPE,
};
pub use define_metadata::ClientMetadata;
pub use endpoint::{
    CanonicalDnsName, CanonicalEndpointHost, EndpointIdentityError, EndpointIdentityErrorReason,
    ValidatedHttpsEndpoint, MAX_DNS_NAME_BYTES, MAX_HTTPS_ENDPOINT_BYTES,
};
pub use error::{OpenId4vpTypeError, OpenId4vpTypeErrorReason};
pub use problem_details::{
    HttpStatusCode, ProblemDetails, ProblemDetailsExt, ProblemInstance, ProblemKind, ProblemTitle,
    ProblemType, PROBLEM_JSON_MEDIA_TYPE,
};
pub use request::{AuthorizationRequestObject, RequestUriMethod, ResponseMode, ResponseType};
pub use response::{
    canonical_authorization_response_bytes, canonical_presentation_json_bytes,
    AuthorizationResponse, PresentationValue, VpToken, MAX_AUTHORIZATION_RESPONSE_JSON_BYTES,
};
pub use transaction_data::{
    canonical_transaction_data_bytes, decode_transaction_data_string,
    encoded_transaction_data_string, TransactionData, TransactionDataHash,
    TransactionDataHashAlgorithm, MAX_TRANSACTION_DATA_JSON_BYTES, MAX_TRANSACTION_DATA_JSON_DEPTH,
};
