// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical wallet-side OpenID4VP authorization response construction.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use reallyme_openid4vp_dcql::{CredentialFormat, QueryId};
use reallyme_openid4vp_types::{
    AuthorizationResponse, PresentationValue, TransactionData, TransactionDataHashAlgorithm,
};

use crate::validate_response_selection::validate_selected_query_coverage;
use crate::{WalletAuthorizationRequest, WalletError, WalletErrorReason};

/// One selected presentation for one verified DCQL Credential Query id.
pub struct WalletSelectedPresentation {
    query_id: QueryId,
    presentation: PresentationValue,
}

impl WalletSelectedPresentation {
    /// Construct a selected presentation.
    #[must_use]
    pub const fn new(query_id: QueryId, presentation: PresentationValue) -> Self {
        Self {
            query_id,
            presentation,
        }
    }

    const fn query_id(&self) -> &QueryId {
        &self.query_id
    }

    fn into_parts(self) -> (QueryId, PresentationValue) {
        let Self {
            query_id,
            presentation,
        } = self;
        (query_id, presentation)
    }
}

impl fmt::Debug for WalletSelectedPresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSelectedPresentation")
            .field("query_id", &self.query_id)
            .field("presentation", &"<redacted>")
            .finish()
    }
}

/// Selected presentations for one verified authorization request.
pub struct WalletSelectedPresentationSet {
    presentations: Vec<WalletSelectedPresentation>,
}

impl WalletSelectedPresentationSet {
    /// Construct selections without transaction data.
    #[must_use]
    pub const fn new(presentations: Vec<WalletSelectedPresentation>) -> Self {
        Self { presentations }
    }

    fn into_presentations(mut self) -> Vec<WalletSelectedPresentation> {
        core::mem::take(&mut self.presentations)
    }
}

impl fmt::Debug for WalletSelectedPresentationSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletSelectedPresentationSet")
            .field("presentation_count", &self.presentations.len())
            .finish()
    }
}

/// Exact proof-verification context for one transaction-bound presentation.
///
/// This context prevents callers from declaring detached hashes. The injected
/// format verifier receives the exact presentation that will be serialized,
/// the selected query and format, and the ordered transaction objects whose
/// digests the authenticated holder proof must contain.
pub struct TransactionDataPresentationVerificationContext<'a> {
    presentation: &'a PresentationValue,
    query_id: &'a QueryId,
    format: &'a CredentialFormat,
    ordered_transaction_data: Vec<&'a TransactionData>,
    algorithm: TransactionDataHashAlgorithm,
}

impl fmt::Debug for TransactionDataPresentationVerificationContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionDataPresentationVerificationContext")
            .field("query_id", self.query_id)
            .field("format", self.format)
            .field(
                "transaction_data_count",
                &self.ordered_transaction_data.len(),
            )
            .field("algorithm", &self.algorithm)
            .field("presentation", &"<redacted>")
            .finish()
    }
}

impl<'a> TransactionDataPresentationVerificationContext<'a> {
    /// Exact presentation value that will be placed in `vp_token`.
    #[must_use]
    pub const fn presentation(&self) -> &'a PresentationValue {
        self.presentation
    }

    /// DCQL credential query selected by the presentation.
    #[must_use]
    pub const fn query_id(&self) -> &'a QueryId {
        self.query_id
    }

    /// Format verifier that must authenticate the holder proof.
    #[must_use]
    pub const fn format(&self) -> &'a CredentialFormat {
        self.format
    }

    /// Ordered transaction objects applicable to this credential query.
    #[must_use]
    pub fn ordered_transaction_data(&self) -> &[&'a TransactionData] {
        &self.ordered_transaction_data
    }

    /// Digest algorithm the authenticated proof must use.
    #[must_use]
    pub const fn algorithm(&self) -> TransactionDataHashAlgorithm {
        self.algorithm
    }
}

/// Trusted format adapter that authenticates transaction-data proof binding.
pub trait TransactionDataPresentationVerifier {
    /// Verify that the exact presentation authenticates the ordered context.
    fn verify_transaction_data_presentation(
        &self,
        context: TransactionDataPresentationVerificationContext<'_>,
    ) -> Result<(), WalletError>;
}

fn transaction_data_for_query<'a>(
    transaction_data: Option<&'a [TransactionData]>,
    query_id: &QueryId,
) -> Vec<&'a TransactionData> {
    transaction_data.map_or_else(Vec::new, |values| {
        values
            .iter()
            .filter(|value| {
                value
                    .credential_ids()
                    .iter()
                    .any(|credential_id| credential_id == query_id.as_str())
            })
            .collect()
    })
}

fn verify_transaction_data_presentations(
    request: &reallyme_openid4vp_types::AuthorizationRequestObject,
    presentations: &[WalletSelectedPresentation],
    verifier: &dyn TransactionDataPresentationVerifier,
) -> Result<(), WalletError> {
    let mut counts = BTreeMap::<QueryId, usize>::new();
    for selected in presentations {
        let credential_query = request
            .dcql_query
            .credentials
            .iter()
            .find(|query| query.id == *selected.query_id())
            .ok_or_else(|| WalletError::new(WalletErrorReason::UnknownSelectedCredentialQuery))?;
        let count = counts.entry(credential_query.id.clone()).or_default();
        *count = count.checked_add(1).ok_or_else(|| {
            WalletError::new(WalletErrorReason::SelectedPresentationCardinalityMismatch)
        })?;
        if !credential_query.multiple && *count > 1 {
            return Err(WalletError::new(
                WalletErrorReason::SelectedPresentationCardinalityMismatch,
            ));
        }

        let ordered_transaction_data =
            transaction_data_for_query(request.transaction_data.as_deref(), selected.query_id());
        if !ordered_transaction_data.is_empty() {
            verifier.verify_transaction_data_presentation(
                TransactionDataPresentationVerificationContext {
                    presentation: &selected.presentation,
                    query_id: selected.query_id(),
                    format: &credential_query.format,
                    ordered_transaction_data,
                    algorithm: TransactionDataHashAlgorithm::Sha256,
                },
            )?;
        }
    }
    Ok(())
}

/// Build a protocol-valid response from presentations selected for a verified request.
pub fn build_authorization_response(
    verified_request: &impl WalletAuthorizationRequest,
    selected: WalletSelectedPresentationSet,
    transaction_data_verifier: &dyn TransactionDataPresentationVerifier,
) -> Result<AuthorizationResponse, WalletError> {
    let request = verified_request.request();
    let presentations = selected.into_presentations();
    if presentations.is_empty() {
        return Err(WalletError::new(
            WalletErrorReason::MissingSelectedPresentation,
        ));
    }

    verify_transaction_data_presentations(request, &presentations, transaction_data_verifier)?;

    let mut allowed_query_ids = BTreeSet::new();
    for credential in &request.dcql_query.credentials {
        allowed_query_ids.insert(credential.id.clone());
    }

    let mut vp_token: BTreeMap<_, Vec<PresentationValue>> = BTreeMap::new();
    for selected in presentations {
        if !allowed_query_ids.contains(selected.query_id()) {
            return Err(WalletError::new(
                WalletErrorReason::UnknownSelectedCredentialQuery,
            ));
        }
        let (query_id, presentation) = selected.into_parts();
        let values = vp_token.entry(query_id.clone()).or_default();
        values.push(presentation);
    }

    validate_selected_query_coverage(request, &vp_token)?;

    Ok(AuthorizationResponse {
        vp_token,
        state: request.state.clone(),
    })
}

#[cfg(test)]
#[path = "build_authorization_response_tests.rs"]
mod tests;
