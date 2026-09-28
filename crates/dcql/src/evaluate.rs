// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map as JsonMap, Value as JsonValue};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::path::process_json_claims_path_with_budget;
use crate::zeroize_json::zeroize_json_value;
use crate::{
    validate_query, ClaimQuery, CredentialFormat, DcqlError, DcqlErrorReason, DcqlQuery, QueryId,
};

#[path = "evaluate_metadata.rs"]
mod metadata;

use metadata::meta_matches;

/// Maximum credential candidates considered in one wallet evaluation.
pub const MAX_EVALUATION_CANDIDATES: usize = 1_024;
/// Maximum conservative comparison work accepted for one evaluation.
pub const MAX_EVALUATION_WORK_UNITS: usize = 1_000_000;

/// Wallet credential candidate supplied to the DCQL engine.
#[derive(Clone)]
pub struct CredentialCandidate {
    /// Wallet-local opaque credential id.
    pub id: EvaluationCredential,
    /// Credential format.
    pub format: CredentialFormat,
    /// Format metadata available before presentation.
    pub meta: JsonMap<String, JsonValue>,
    /// JSON claim view used for DCQL claim path processing.
    pub claims: JsonValue,
    /// Whether the credential can produce a cryptographic holder-binding proof.
    pub cryptographic_holder_binding: bool,
}

impl fmt::Debug for CredentialCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialCandidate")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("meta", &"<redacted>")
            .field("claims", &"<redacted>")
            .field(
                "cryptographic_holder_binding",
                &self.cryptographic_holder_binding,
            )
            .finish()
    }
}

impl Zeroize for CredentialCandidate {
    fn zeroize(&mut self) {
        self.id.zeroize();
        let meta = core::mem::take(&mut self.meta);
        for (mut key, mut value) in meta {
            key.zeroize();
            zeroize_json_value(&mut value);
        }
        zeroize_json_value(&mut self.claims);
    }
}

impl Drop for CredentialCandidate {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for CredentialCandidate {}

/// Opaque wallet-local credential identifier in evaluation results.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvaluationCredential(String);

impl fmt::Debug for EvaluationCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvaluationCredential")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for EvaluationCredential {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for EvaluationCredential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for EvaluationCredential {}

impl EvaluationCredential {
    /// Construct an evaluation credential id.
    pub fn new(value: String) -> Result<Self, DcqlError> {
        if value.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::EmptyValue));
        }
        Ok(Self(value))
    }

    /// Return the wallet-local id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Result of evaluating a DCQL query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Credential query matches.
    pub matches: Vec<CredentialMatch>,
}

/// Credentials that satisfy one Credential Query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialMatch {
    /// DCQL Credential Query id.
    pub query_id: QueryId,
    /// Per-credential disclosure selections satisfying the query.
    pub credentials: Vec<CredentialSelection>,
}

/// One matching credential and its own disclosure selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialSelection {
    /// Wallet-local credential id.
    pub credential_id: EvaluationCredential,
    /// Claims selected for this exact credential.
    pub claims: SelectedClaims,
}

/// Disclosure semantics selected while evaluating one credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectedClaims {
    /// The query omitted `claims`; the credential itself is requested.
    NoClaimsRequested,
    /// `claims` was present without alternatives, so every claim is required.
    AllRequired,
    /// The first satisfiable verifier-preferred `claim_sets` option.
    ClaimSet(Vec<QueryId>),
}

/// Evaluate a validated DCQL query against wallet credential candidates.
pub fn evaluate_query(
    query: &DcqlQuery,
    candidates: &[CredentialCandidate],
) -> Result<Evaluation, DcqlError> {
    validate_query(query)?;
    validate_evaluation_budget(query, candidates.len())?;
    let mut remaining_work = MAX_EVALUATION_WORK_UNITS;

    let mut all_matches = Vec::with_capacity(query.credentials.len());
    for credential_query in &query.credentials {
        let mut credentials = Vec::new();
        for candidate in candidates {
            if let Some(candidate_claim_ids) =
                credential_matches_query(credential_query, candidate, &mut remaining_work)?
            {
                let claims = match (
                    credential_query.claims.as_ref(),
                    credential_query.claim_sets.as_ref(),
                ) {
                    (None, _) => SelectedClaims::NoClaimsRequested,
                    (Some(_), None) => SelectedClaims::AllRequired,
                    (Some(_), Some(_)) => SelectedClaims::ClaimSet(candidate_claim_ids),
                };
                credentials.push(CredentialSelection {
                    credential_id: candidate.id.clone(),
                    claims,
                });
                if !credential_query.multiple {
                    break;
                }
            }
        }
        all_matches.push(CredentialMatch {
            query_id: credential_query.id.clone(),
            credentials,
        });
    }

    enforce_credential_sets(query, &all_matches)?;
    Ok(Evaluation {
        matches: all_matches,
    })
}

fn validate_evaluation_budget(query: &DcqlQuery, candidate_count: usize) -> Result<(), DcqlError> {
    if candidate_count > MAX_EVALUATION_CANDIDATES {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    let mut units = 0_usize;
    for credential in &query.credentials {
        let mut per_candidate = 1_usize;
        if let Some(claims) = credential.claims.as_ref() {
            for claim in claims {
                let value_count = claim.values.as_ref().map_or(1, Vec::len);
                let claim_units = claim
                    .path
                    .components()
                    .len()
                    .checked_add(value_count)
                    .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
                per_candidate = per_candidate
                    .checked_add(claim_units)
                    .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
            }
        }
        let credential_units = per_candidate
            .checked_mul(candidate_count)
            .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
        units = units
            .checked_add(credential_units)
            .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
        if units > MAX_EVALUATION_WORK_UNITS {
            return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
        }
    }
    Ok(())
}

/// Determine whether one already-validated credential satisfies one query.
///
/// Verifier-side format adapters use this after cryptographic verification to
/// enforce the same format metadata and claim semantics used for wallet-side
/// candidate selection. Keeping one matcher prevents the two roles from
/// drifting on `vct_values`, mdoc document types, or claims-path behavior.
pub fn credential_satisfies_query(
    query: &crate::CredentialQuery,
    candidate: &CredentialCandidate,
) -> Result<bool, DcqlError> {
    let mut remaining_work = MAX_EVALUATION_WORK_UNITS;
    Ok(credential_matches_query(query, candidate, &mut remaining_work)?.is_some())
}

/// Validate a selected set of Credential Query ids against DCQL requirements.
///
/// Wallet construction and verifier response validation must use this same
/// function so required credential-set alternatives cannot drift between roles.
/// The query must already have passed [`validate_query`] at its input boundary.
pub fn validate_query_selection(
    query: &DcqlQuery,
    selected_query_ids: &BTreeSet<QueryId>,
) -> Result<(), DcqlError> {
    validate_query_selection_inner(query, selected_query_ids)
}

fn credential_matches_query(
    query: &crate::CredentialQuery,
    candidate: &CredentialCandidate,
    remaining_work: &mut usize,
) -> Result<Option<Vec<QueryId>>, DcqlError> {
    consume_evaluation_work(remaining_work, 1)?;
    if query.format != candidate.format {
        return Ok(None);
    }
    if query.require_cryptographic_holder_binding && !candidate.cryptographic_holder_binding {
        return Ok(None);
    }
    if query.trusted_authorities.is_some() {
        // Candidate metadata is not authenticated authority evidence. Until a
        // format verifier supplies typed AKI, ETSI trust-list, or federation
        // receipts, both wallet selection and verifier-side matching must fail
        // closed instead of treating this member as an informational hint.
        return Ok(None);
    }
    if !meta_matches(&query.format, &query.meta, &candidate.meta, remaining_work)? {
        return Ok(None);
    }

    let Some(claims) = query.claims.as_ref() else {
        return Ok(Some(Vec::new()));
    };

    let Some(claim_sets) = query.claim_sets.as_ref() else {
        let mut matching_claim_ids = Vec::new();
        for claim in claims {
            if !claim_matches_candidate(claim, &candidate.claims, remaining_work)? {
                return Ok(None);
            }
            if let Some(id) = claim.id.as_ref() {
                matching_claim_ids.push(id.clone());
            }
        }
        return Ok(Some(matching_claim_ids));
    };

    let mut claim_matches = BTreeMap::new();
    for claim in claims {
        let Some(id) = claim.id.as_ref() else {
            continue;
        };
        claim_matches.insert(
            id.as_str(),
            claim_matches_candidate(claim, &candidate.claims, remaining_work)?,
        );
    }

    for claim_set in claim_sets {
        let mut matching_claim_ids = Vec::with_capacity(claim_set.0.len());
        let mut set_matches = true;
        for claim_id in &claim_set.0 {
            let Some(matches) = claim_matches.get(claim_id.as_str()) else {
                return Err(DcqlError::new(DcqlErrorReason::UnknownReference));
            };

            if !matches {
                set_matches = false;
                break;
            }
            matching_claim_ids.push(claim_id.clone());
        }
        if set_matches {
            return Ok(Some(matching_claim_ids));
        }
    }

    Ok(None)
}

fn claim_matches_candidate(
    claim: &ClaimQuery,
    credential_claims: &JsonValue,
    remaining_work: &mut usize,
) -> Result<bool, DcqlError> {
    let values = match process_json_claims_path_with_budget(
        credential_claims,
        &claim.path,
        remaining_work,
    ) {
        Ok(values) => values,
        Err(error) if error.reason() == DcqlErrorReason::ClaimsPathMismatch => return Ok(false),
        Err(error) => return Err(error),
    };

    let Some(expected_values) = claim.values.as_ref() else {
        return Ok(true);
    };

    // Charge the exact nested comparison count as it occurs. Charging only
    // each resolved candidate value would let an attacker multiply work by
    // supplying a large `values` array in the query.
    for actual in values.values().iter().copied() {
        for expected in expected_values {
            consume_evaluation_work(remaining_work, 1)?;
            if expected.matches_json(actual) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn consume_evaluation_work(remaining_work: &mut usize, units: usize) -> Result<(), DcqlError> {
    *remaining_work = remaining_work
        .checked_sub(units)
        .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
    Ok(())
}

fn enforce_credential_sets(
    query: &DcqlQuery,
    matches: &[CredentialMatch],
) -> Result<(), DcqlError> {
    let matched_query_ids = matches
        .iter()
        .filter(|item| !item.credentials.is_empty())
        .map(|item| item.query_id.clone())
        .collect::<BTreeSet<_>>();

    validate_query_selection_inner(query, &matched_query_ids)
}

fn validate_query_selection_inner(
    query: &DcqlQuery,
    selected_query_ids: &BTreeSet<QueryId>,
) -> Result<(), DcqlError> {
    let known_query_ids = query
        .credentials
        .iter()
        .map(|credential| credential.id.clone())
        .collect::<BTreeSet<_>>();
    if !selected_query_ids.is_subset(&known_query_ids) {
        return Err(DcqlError::new(DcqlErrorReason::UnknownReference));
    }

    let Some(credential_sets) = query.credential_sets.as_ref() else {
        if selected_query_ids == &known_query_ids {
            return Ok(());
        }
        return Err(DcqlError::new(
            DcqlErrorReason::UnsatisfiedRequiredCredential,
        ));
    };

    for credential_set in credential_sets {
        if !credential_set.required {
            continue;
        }
        let satisfied = credential_set.options.iter().any(|option| {
            option
                .iter()
                .all(|query_id| selected_query_ids.contains(query_id))
        });
        if !satisfied {
            return Err(DcqlError::new(
                DcqlErrorReason::UnsatisfiedRequiredCredential,
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod tests;
