// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance vector runner.
//!
//! Each vector names a `target` and an expected accept/reject outcome. JSON
//! targets first pass through the strict JSON guard so duplicate object names
//! and pathological nesting are caught before serde-based protocol parsing.

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, AuthorizationResponse, ClientIdentifier, PresentationValue,
};
use reallyme_openid4vp_verifier::{
    diagnose_authorization_response_with_options, HolderBindingClaims,
    HolderBindingVerificationContext, HolderBindingVerifier, RequestBinding,
    ResponseValidationOptions, SessionRecord, VerifiedDisclosureSet, VerifiedHolderBinding,
    VerifiedTrustProvenance, VerifierError,
};
use reallyme_openid4vp_wallet::{
    parse_authorization_request_transport, validate_wallet_request_object, RequestTransportPolicy,
};
use serde_json::{json, Map as JsonMap};

use crate::error::{ConformanceError, ConformanceResult};
use crate::strict_json::validate_strict_json;
use crate::vector::{ConformanceVector, ExpectedResult};

/// Outcome of running one conformance vector against the implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorOutcome {
    /// The parser's accept/reject behavior matched the expectation.
    Passed,
    /// The parser accepted a payload the vector expected it to reject.
    UnexpectedAccept,
    /// The parser rejected a payload the vector expected it to accept.
    UnexpectedReject,
}

impl VectorOutcome {
    /// Returns true when the vector behaved as expected.
    #[must_use]
    pub const fn passed(self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// Runs one vector and compares implementation behavior with the expectation.
pub fn run_vector(vector: &ConformanceVector) -> ConformanceResult<VectorOutcome> {
    let accepted = dispatch(&vector.target, &vector.input)?;
    let expected_accept = matches!(vector.expected, ExpectedResult::Accept);
    Ok(match (accepted, expected_accept) {
        (true, true) | (false, false) => VectorOutcome::Passed,
        (true, false) => VectorOutcome::UnexpectedAccept,
        (false, true) => VectorOutcome::UnexpectedReject,
    })
}

/// Runs every vector, returning each vector's id paired with its outcome.
pub fn run_vectors(
    vectors: &[ConformanceVector],
) -> ConformanceResult<Vec<(String, VectorOutcome)>> {
    let mut results = Vec::with_capacity(vectors.len());
    for vector in vectors {
        results.push((vector.id.clone(), run_vector(vector)?));
    }
    Ok(results)
}

fn dispatch(target: &str, input: &str) -> ConformanceResult<bool> {
    let accepted = match target {
        "dcql::DcqlQuery" => {
            validate_strict_json(input)?;
            DcqlQuery::from_json_slice(input.as_bytes()).is_ok()
        }
        "types::AuthorizationRequestObject" => {
            validate_strict_json(input)?;
            let request = serde_json::from_str::<AuthorizationRequestObject>(input);
            match request {
                Ok(value) => {
                    validate_wallet_request_object(&value, Some("https://rp.example"), 10).is_ok()
                }
                Err(_) => false,
            }
        }
        "types::AuthorizationResponse" => {
            validate_strict_json(input)?;
            let response = serde_json::from_str::<AuthorizationResponse>(input);
            match response {
                Ok(value) => match session() {
                    Some(session) => diagnose_authorization_response_with_options(
                        &session,
                        &value,
                        10,
                        ResponseValidationOptions {
                            holder_binding_verifier: Some(&FixtureHolderBindingVerifier),
                        },
                    )
                    .is_ok(),
                    None => false,
                },
                Err(_) => false,
            }
        }
        "wallet::AuthorizationRequestTransport" => {
            parse_authorization_request_transport(input, RequestTransportPolicy::default()).is_ok()
        }
        "security::StrictJson" => validate_strict_json(input).is_ok(),
        _ => return Err(ConformanceError::UnknownTarget),
    };
    Ok(accepted)
}

struct FixtureHolderBindingVerifier;

impl HolderBindingVerifier for FixtureHolderBindingVerifier {
    fn verify_holder_binding(
        &self,
        _presentation: &PresentationValue,
        _context: HolderBindingVerificationContext<'_>,
    ) -> Result<VerifiedHolderBinding, VerifierError> {
        Ok(VerifiedHolderBinding::new(
            HolderBindingClaims {
                audience: vec!["x509_san_dns:verifier.example".to_owned()],
                nonce: "0123456789abcdef".to_owned(),
                expiration_unix: 100,
                issued_at_unix: 10,
                sd_hash: None,
                transaction_data_hashes: Vec::new(),
                transaction_data_hashes_alg: None,
            },
            VerifiedDisclosureSet::Derived,
            VerifiedTrustProvenance::VerifiedDerivedProof,
        ))
    }
}

fn session() -> Option<SessionRecord> {
    Some(SessionRecord {
        binding: RequestBinding {
            client_id: fallback_client_identifier()?,
            nonce: "0123456789abcdef".to_owned(),
            response_uri: Some("https://verifier.example/response".to_owned()),
            redirect_uri: None,
            dc_api_origin: None,
            expiry_unix: 100,
            transaction_data_bindings: Vec::new(),
        },
        state: Some("fedcba9876543210".to_owned()),
        dcql_query: fallback_dcql_query(),
        response_mode: reallyme_openid4vp_types::ResponseMode::DirectPost,
        mdoc_session_transcript: None,
        post_response_redirect_uri: None,
        follow_back_requirement: None,
    })
}

fn fallback_dcql_query() -> DcqlQuery {
    let query_id = match QueryId::parse("pid") {
        Ok(query_id) => query_id,
        Err(_) => return empty_dcql_query(),
    };
    let format = match CredentialFormat::new(CredentialFormat::DC_SD_JWT.to_owned()) {
        Ok(format) => format,
        Err(_) => return empty_dcql_query(),
    };
    DcqlQuery {
        credentials: vec![CredentialQuery {
            id: query_id,
            format,
            multiple: false,
            meta: fallback_sd_jwt_meta(),
            trusted_authorities: None,
            require_cryptographic_holder_binding: true,
            claims: None,
            claim_sets: None,
        }],
        credential_sets: None,
    }
}

fn fallback_sd_jwt_meta() -> JsonMap<String, serde_json::Value> {
    JsonMap::from_iter([(
        "vct_values".to_owned(),
        json!(["https://credentials.example.com/identity_credential"]),
    )])
}

fn empty_dcql_query() -> DcqlQuery {
    DcqlQuery {
        credentials: Vec::new(),
        credential_sets: None,
    }
}

fn fallback_client_identifier() -> Option<ClientIdentifier> {
    ClientIdentifier::parse("x509_san_dns:verifier.example").ok()
}
