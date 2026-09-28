// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! DCQL query model, validation, and wallet-side evaluation.
//!
//! The crate intentionally has no OpenID4VP transport dependencies. It models
//! the OpenID4VP 1.0 final DCQL structures and evaluates them against an
//! injected inventory of wallet credentials.
//!
//! Serde implementations in this crate exist only for bounded internal
//! protocol parsing. They are not stable SDK DTO contracts. Cross-language and
//! SDK boundaries must carry DCQL as validated canonical JSON bytes inside the
//! generated OpenID4VP protobuf contract.

mod error;
mod evaluate;
mod model;
mod model_debug;
mod path;
mod validate;
mod zeroize_json;

pub use error::{DcqlError, DcqlErrorReason};
pub use evaluate::{
    credential_satisfies_query, evaluate_query, validate_query_selection, CredentialCandidate,
    CredentialMatch, CredentialSelection, Evaluation, EvaluationCredential, SelectedClaims,
};
pub use model::{
    ClaimQuery, ClaimSet, ClaimValue, ClaimsPath, ClaimsPathComponent, CredentialFormat,
    CredentialQuery, CredentialSetQuery, DcqlQuery, QueryId, TrustedAuthorityQuery,
    MAX_DCQL_JSON_BYTES,
};
pub use path::{process_json_claims_path, ProcessedClaimValues};
pub use validate::validate_query;
