// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::WalletAuthorizationRequest;
use reallyme_openid4vp_dcql::{evaluate_query, CredentialCandidate, DcqlError, Evaluation};

/// Prepare wallet consent data by evaluating the request DCQL query.
pub fn prepare_consent_data(
    verified_request: &impl WalletAuthorizationRequest,
    candidates: &[CredentialCandidate],
) -> Result<Evaluation, DcqlError> {
    evaluate_query(&verified_request.request().dcql_query, candidates)
}
