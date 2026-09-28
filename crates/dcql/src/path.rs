// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;
use serde_json::Value as JsonValue;

use crate::{ClaimsPath, ClaimsPathComponent, DcqlError, DcqlErrorReason};

/// Maximum intermediate values selected while evaluating one claims path.
pub const MAX_PROCESSED_CLAIM_VALUES: usize = 4_096;

/// JSON values selected by a claims path pointer.
#[derive(Clone)]
pub struct ProcessedClaimValues<'a> {
    values: Vec<&'a JsonValue>,
}

impl fmt::Debug for ProcessedClaimValues<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessedClaimValues")
            .field("value_count", &self.values.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl<'a> ProcessedClaimValues<'a> {
    /// Return selected JSON values.
    pub fn values(&self) -> &[&'a JsonValue] {
        &self.values
    }
}

/// Process a DCQL claims path pointer against a JSON credential.
pub fn process_json_claims_path<'a>(
    credential: &'a JsonValue,
    path: &ClaimsPath,
) -> Result<ProcessedClaimValues<'a>, DcqlError> {
    let mut remaining_work = usize::MAX;
    process_json_claims_path_with_budget(credential, path, &mut remaining_work)
}

pub(crate) fn process_json_claims_path_with_budget<'a>(
    credential: &'a JsonValue,
    path: &ClaimsPath,
    remaining_work: &mut usize,
) -> Result<ProcessedClaimValues<'a>, DcqlError> {
    if path.components().is_empty() {
        return Err(DcqlError::new(DcqlErrorReason::InvalidClaimsPath));
    }

    let mut values = vec![credential];

    for component in path.components() {
        apply_path_component(component, &mut values, remaining_work)?;
        if values.is_empty() {
            return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
        }
    }

    Ok(ProcessedClaimValues { values })
}

fn apply_path_component(
    component: &ClaimsPathComponent,
    values: &mut Vec<&JsonValue>,
    remaining_work: &mut usize,
) -> Result<(), DcqlError> {
    let mut selected = Vec::with_capacity(values.len());
    for value in values.iter().copied() {
        consume_work(remaining_work, 1)?;
        match component {
            ClaimsPathComponent::Name(name) => {
                let JsonValue::Object(object) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                if let Some(next) = object.get(name) {
                    ensure_selection_capacity(selected.len(), 1)?;
                    selected.push(next);
                }
            }
            ClaimsPathComponent::Index(index) => {
                let JsonValue::Array(array) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                let index = usize::try_from(*index)
                    .map_err(|_| DcqlError::new(DcqlErrorReason::InvalidClaimsPath))?;
                if let Some(next) = array.get(index) {
                    ensure_selection_capacity(selected.len(), 1)?;
                    selected.push(next);
                }
            }
            ClaimsPathComponent::All => {
                let JsonValue::Array(array) = value else {
                    return Err(DcqlError::new(DcqlErrorReason::ClaimsPathMismatch));
                };
                ensure_selection_capacity(selected.len(), array.len())?;
                consume_work(remaining_work, array.len())?;
                selected.extend(array.iter());
            }
        }
    }
    values.clear();
    values.extend(selected);
    Ok(())
}

fn consume_work(remaining_work: &mut usize, units: usize) -> Result<(), DcqlError> {
    *remaining_work = remaining_work
        .checked_sub(units)
        .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
    Ok(())
}

fn ensure_selection_capacity(current: usize, additional: usize) -> Result<(), DcqlError> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
    if total > MAX_PROCESSED_CLAIM_VALUES {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    Ok(())
}
