// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_dcql::QueryId;
use reallyme_openid4vp_types::TransactionDataHashAlgorithm;
use subtle::ConstantTimeEq;

use crate::{HolderBindingClaims, RequestBinding, VerifierError, VerifierErrorReason};

pub(crate) fn validate_transaction_data_binding(
    binding: &RequestBinding,
    query_id: &QueryId,
    claims: &HolderBindingClaims,
) -> Result<(), VerifierError> {
    let expected = binding
        .transaction_data_bindings
        .iter()
        .filter(|expected| &expected.query_id == query_id)
        .collect::<Vec<_>>();
    if expected.is_empty() {
        if !claims.transaction_data_hashes.is_empty()
            || claims.transaction_data_hashes_alg.is_some()
        {
            return Err(invalid_binding());
        }
        return Ok(());
    }

    // OpenID4VP defines SHA-256 as the default when the proof omits the
    // algorithm member. An explicit value must still match every ordered item.
    let actual_algorithm = claims
        .transaction_data_hashes_alg
        .unwrap_or(TransactionDataHashAlgorithm::Sha256);
    if claims.transaction_data_hashes.len() != expected.len()
        || expected
            .iter()
            .any(|binding| binding.algorithm != actual_algorithm)
        || claims
            .transaction_data_hashes
            .iter()
            .zip(expected)
            .any(|(actual, expected)| !bool::from(actual.ct_eq(&expected.digest)))
    {
        return Err(invalid_binding());
    }
    Ok(())
}

fn invalid_binding() -> VerifierError {
    VerifierError::new(VerifierErrorReason::InvalidBinding)
}
