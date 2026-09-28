// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::{BTreeMap, BTreeSet};

use reallyme_openid4vp_dcql::{validate_query_selection, QueryId};
use reallyme_openid4vp_types::{AuthorizationRequestObject, PresentationValue};

use crate::{WalletError, WalletErrorReason};

pub(crate) fn validate_selected_query_coverage(
    request: &AuthorizationRequestObject,
    presentations: &BTreeMap<QueryId, Vec<PresentationValue>>,
) -> Result<(), WalletError> {
    let selected_query_ids = presentations.keys().cloned().collect::<BTreeSet<_>>();
    validate_query_selection(&request.dcql_query, &selected_query_ids)
        .map_err(|_| WalletError::new(WalletErrorReason::UnsatisfiedRequiredCredentialQuery))
}
