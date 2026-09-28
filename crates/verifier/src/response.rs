// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::BTreeSet;

use reallyme_openid4vp_dcql::{validate_query_selection, QueryId};
use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, parse_zk_presentation_value, validate_zk_presentation_binding,
};
use reallyme_openid4vp_types::AuthorizationResponse;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::compare_secret::constant_time_str_eq;
use crate::{
    validate_request_binding, HolderBindingVerificationContext, HolderBindingVerifier,
    SessionRecord, VerifiedHolderBinding, VerifierError, VerifierErrorReason,
    MIN_SESSION_BINDING_BYTES,
};

/// Response-validation dependencies and policy.
#[derive(Clone, Copy, Default)]
pub struct ResponseValidationOptions<'a> {
    /// Verifier for presentation holder-binding proofs.
    pub holder_binding_verifier: Option<&'a dyn HolderBindingVerifier>,
}

/// Successful, non-authorizing response diagnostics.
///
/// This value proves only that the supplied in-memory values were internally
/// consistent at one instant. It does not reserve or consume a session, persist
/// a result, or authorize disclosure. Authorization belongs to the runtime's
/// store-backed reservation/commit operation.
#[derive(Clone, PartialEq, Eq)]
pub struct NonAuthorizingResponseDiagnostics {
    verified_presentations: Vec<VerifiedPresentation>,
}

impl NonAuthorizingResponseDiagnostics {
    /// Borrow the exact typed presentation results produced during validation.
    #[must_use]
    pub fn verified_presentations(&self) -> &[VerifiedPresentation] {
        &self.verified_presentations
    }

    /// Transfer the verified presentation results to a durable runtime commit.
    #[must_use]
    pub fn into_verified_presentations(mut self) -> Vec<VerifiedPresentation> {
        core::mem::take(&mut self.verified_presentations)
    }
}

impl core::fmt::Debug for NonAuthorizingResponseDiagnostics {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NonAuthorizingResponseDiagnostics")
            .field(
                "verified_presentation_count",
                &self.verified_presentations.len(),
            )
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for NonAuthorizingResponseDiagnostics {
    fn zeroize(&mut self) {
        self.verified_presentations.zeroize();
    }
}

impl Drop for NonAuthorizingResponseDiagnostics {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for NonAuthorizingResponseDiagnostics {}

/// One immutable presentation result bound to its query and exact bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPresentation {
    query_id: QueryId,
    presentation_sha256: [u8; 32],
    holder_binding: VerifiedHolderBinding,
}

impl VerifiedPresentation {
    /// DCQL query whose constraints this presentation satisfied.
    #[must_use]
    pub const fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    /// SHA-256 of the exact compact bytes or canonical typed JSON presentation.
    #[must_use]
    pub const fn presentation_sha256(&self) -> &[u8; 32] {
        &self.presentation_sha256
    }

    /// Authenticated disclosures and trust provenance from the format verifier.
    #[must_use]
    pub const fn holder_binding(&self) -> &VerifiedHolderBinding {
        &self.holder_binding
    }
}

impl core::fmt::Debug for VerifiedPresentation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedPresentation")
            .field("query_id", &self.query_id)
            .field("trust_provenance", &self.holder_binding.trust_provenance())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for VerifiedPresentation {
    fn zeroize(&mut self) {
        self.query_id.zeroize();
        self.presentation_sha256.zeroize();
        self.holder_binding.zeroize();
    }
}

impl Drop for VerifiedPresentation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VerifiedPresentation {}

/// Validate a final OpenID4VP Authorization Response against verifier session state.
///
/// This ports the useful meproto response guard while preserving final-spec
/// response shape: `vp_token` is a DCQL-query-id-keyed object rather than the
/// old vector of opaque VP bytes.
pub fn diagnose_authorization_response(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
) -> Result<NonAuthorizingResponseDiagnostics, VerifierError> {
    diagnose_authorization_response_with_options(
        session,
        response,
        now_unix,
        ResponseValidationOptions::default(),
    )
}

/// Validate an Authorization Response with explicit format verifiers.
pub fn diagnose_authorization_response_with_options(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<NonAuthorizingResponseDiagnostics, VerifierError> {
    validate_request_binding(&session.binding, now_unix)?;

    if session
        .state
        .as_ref()
        .is_some_and(|state| state.len() < MIN_SESSION_BINDING_BYTES)
        || !optional_secret_eq(response.state.as_deref(), session.state.as_deref())
    {
        return Err(VerifierError::new(VerifierErrorReason::SessionMismatch));
    }

    if response.vp_token.is_empty() {
        return Err(VerifierError::new(VerifierErrorReason::EmptyVpToken));
    }

    validate_vp_token_query_coverage(session, response)?;
    if response
        .vp_token
        .values()
        .any(|presentations| presentations.is_empty())
    {
        return Err(VerifierError::new(
            VerifierErrorReason::EmptyPresentationList,
        ));
    }

    let verified_presentations = validate_presentations(session, response, now_unix, options)?;

    Ok(NonAuthorizingResponseDiagnostics {
        verified_presentations,
    })
}

fn validate_vp_token_query_coverage(
    session: &SessionRecord,
    response: &AuthorizationResponse,
) -> Result<(), VerifierError> {
    let actual_ids = response
        .vp_token
        .keys()
        .cloned()
        .collect::<BTreeSet<QueryId>>();
    validate_query_selection(&session.dcql_query, &actual_ids)
        .map_err(|_| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
    for query in &session.dcql_query.credentials {
        if !query.multiple
            && response
                .vp_token
                .get(&query.id)
                .is_some_and(|presentations| presentations.len() > 1)
        {
            return Err(VerifierError::new(
                VerifierErrorReason::VpTokenCardinalityMismatch,
            ));
        }
    }
    Ok(())
}

fn optional_secret_eq(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => constant_time_str_eq(left, right),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

fn validate_presentations(
    session: &SessionRecord,
    response: &AuthorizationResponse,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<Vec<VerifiedPresentation>, VerifierError> {
    let mut verified_presentations = Vec::new();
    for (query_id, presentations) in &response.vp_token {
        let credential_query = session
            .dcql_query
            .credentials
            .iter()
            .find(|query| &query.id == query_id)
            .ok_or_else(|| VerifierError::new(VerifierErrorReason::VpTokenQueryMismatch))?;
        for presentation in presentations {
            if let Some(zk_presentation) = parse_zk_presentation_value(presentation)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?
            {
                let transaction_data_hash = zk_transaction_data_hash(session, query_id)?;
                let expected_binding = build_zk_presentation_binding(
                    &session.binding.nonce,
                    &session.binding.client_id.to_wire_value(),
                    transaction_data_hash,
                );
                validate_zk_presentation_binding(&zk_presentation.binding, &expected_binding)
                    .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidZkPresentation))?;
            }
            let holder_binding = validate_holder_bound_presentation(
                session,
                credential_query,
                presentation,
                now_unix,
                options,
            )?;
            verified_presentations.push(VerifiedPresentation {
                query_id: query_id.clone(),
                presentation_sha256: presentation_sha256(presentation)?,
                holder_binding,
            });
        }
    }
    Ok(verified_presentations)
}

fn zk_transaction_data_hash(
    session: &SessionRecord,
    query_id: &QueryId,
) -> Result<Option<[u8; 32]>, VerifierError> {
    let mut matches = session
        .binding
        .transaction_data_bindings
        .iter()
        .filter(|binding| &binding.query_id == query_id);
    let first = matches.next().map(|binding| binding.digest);
    if matches.next().is_some() {
        // The current ZK envelope has one fixed transaction digest public
        // input. Accepting only the first element would silently discard the
        // ordered transaction-data semantics required by OpenID4VP.
        return Err(VerifierError::new(VerifierErrorReason::InvalidBinding));
    }
    Ok(first)
}

fn validate_holder_bound_presentation(
    session: &SessionRecord,
    credential_query: &reallyme_openid4vp_dcql::CredentialQuery,
    presentation: &reallyme_openid4vp_types::PresentationValue,
    now_unix: u64,
    options: ResponseValidationOptions<'_>,
) -> Result<VerifiedHolderBinding, VerifierError> {
    let Some(verifier) = options.holder_binding_verifier else {
        return Err(VerifierError::new(VerifierErrorReason::UnsupportedFormat));
    };
    let verified = verifier.verify_holder_binding(
        presentation,
        HolderBindingVerificationContext::new(session, credential_query, now_unix),
    )?;
    crate::holder_binding::validate_holder_binding_claims_for_query(
        &session.binding,
        Some(&credential_query.id),
        verified.claims(),
        now_unix,
    )?;
    Ok(verified)
}

fn presentation_sha256(
    presentation: &reallyme_openid4vp_types::PresentationValue,
) -> Result<[u8; 32], VerifierError> {
    let digest = match presentation {
        reallyme_openid4vp_types::PresentationValue::Compact(value) => {
            Sha256::digest(value.as_bytes())
        }
        reallyme_openid4vp_types::PresentationValue::Json(value) => {
            let encoded = reallyme_openid4vp_types::canonical_presentation_json_bytes(value)
                .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidBinding))?;
            Sha256::digest(encoded.as_slice())
        }
    };
    Ok(digest.into())
}

#[cfg(test)]
#[path = "response_tests.rs"]
mod tests;
