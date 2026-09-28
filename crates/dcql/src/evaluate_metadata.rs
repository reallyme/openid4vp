// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::{Map as JsonMap, Value as JsonValue};

use super::consume_evaluation_work;
use crate::{CredentialFormat, DcqlError, DcqlErrorReason};

pub(super) fn meta_matches(
    format: &CredentialFormat,
    expected: &JsonMap<String, JsonValue>,
    actual: &JsonMap<String, JsonValue>,
    remaining_work: &mut usize,
) -> Result<bool, DcqlError> {
    match format.as_str() {
        CredentialFormat::DC_SD_JWT => vct_values_match(expected, actual, remaining_work),
        CredentialFormat::MSO_MDOC => {
            let Some(expected_doctype) = expected.get("doctype_value").and_then(JsonValue::as_str)
            else {
                return Ok(false);
            };
            consume_evaluation_work(remaining_work, 1)?;
            Ok(actual.get("doctype_value").and_then(JsonValue::as_str) == Some(expected_doctype))
        }
        _ => generic_meta_matches(expected, actual, remaining_work),
    }
}

fn vct_values_match(
    expected: &JsonMap<String, JsonValue>,
    actual: &JsonMap<String, JsonValue>,
    remaining_work: &mut usize,
) -> Result<bool, DcqlError> {
    let Some(allowed) = expected.get("vct_values").and_then(JsonValue::as_array) else {
        return Ok(false);
    };
    if allowed.is_empty() {
        return Ok(false);
    }

    // Validate the complete arrays before matching. This preserves fail-closed
    // behavior for malformed candidate metadata even if an earlier item would
    // otherwise match, while charging attacker-controlled traversal.
    for value in allowed {
        consume_evaluation_work(remaining_work, 1)?;
        if value.as_str().is_none() {
            return Ok(false);
        }
    }

    if let Some(candidate_vct) = actual.get("vct").and_then(JsonValue::as_str) {
        for allowed_value in allowed {
            consume_evaluation_work(remaining_work, 1)?;
            if allowed_value.as_str() == Some(candidate_vct) {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    let Some(candidate_values) = actual.get("vct_values").and_then(JsonValue::as_array) else {
        return Ok(false);
    };
    for candidate in candidate_values {
        consume_evaluation_work(remaining_work, 1)?;
        if candidate.as_str().is_none() {
            return Ok(false);
        }
    }

    for candidate in candidate_values {
        let Some(candidate) = candidate.as_str() else {
            return Ok(false);
        };
        for allowed_value in allowed {
            consume_evaluation_work(remaining_work, 1)?;
            if allowed_value.as_str() == Some(candidate) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn generic_meta_matches(
    expected: &JsonMap<String, JsonValue>,
    actual: &JsonMap<String, JsonValue>,
    remaining_work: &mut usize,
) -> Result<bool, DcqlError> {
    for (key, expected_value) in expected {
        consume_evaluation_work(remaining_work, 1)?;
        let Some(actual_value) = actual.get(key) else {
            return Ok(false);
        };
        if !json_values_equal(expected_value, actual_value, remaining_work)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn json_values_equal(
    expected: &JsonValue,
    actual: &JsonValue,
    remaining_work: &mut usize,
) -> Result<bool, DcqlError> {
    let mut pending = Vec::new();
    push_comparison(&mut pending, expected, actual, remaining_work)?;

    while let Some((expected_value, actual_value)) = pending.pop() {
        consume_evaluation_work(remaining_work, 1)?;
        match (expected_value, actual_value) {
            (JsonValue::Array(expected_items), JsonValue::Array(actual_items)) => {
                if expected_items.len() != actual_items.len() {
                    return Ok(false);
                }
                reserve_comparisons(&mut pending, expected_items.len(), remaining_work)?;
                for (expected_item, actual_item) in expected_items.iter().zip(actual_items).rev() {
                    pending.push((expected_item, actual_item));
                }
            }
            (JsonValue::Object(expected_map), JsonValue::Object(actual_map)) => {
                if expected_map.len() != actual_map.len() {
                    return Ok(false);
                }
                reserve_comparisons(&mut pending, expected_map.len(), remaining_work)?;
                for (key, expected_item) in expected_map.iter().rev() {
                    let Some(actual_item) = actual_map.get(key) else {
                        return Ok(false);
                    };
                    pending.push((expected_item, actual_item));
                }
            }
            (JsonValue::Null, JsonValue::Null) => {}
            (JsonValue::Bool(expected), JsonValue::Bool(actual)) if expected == actual => {}
            (JsonValue::Number(expected), JsonValue::Number(actual)) if expected == actual => {}
            (JsonValue::String(expected), JsonValue::String(actual)) if expected == actual => {}
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn push_comparison<'a>(
    pending: &mut Vec<(&'a JsonValue, &'a JsonValue)>,
    expected: &'a JsonValue,
    actual: &'a JsonValue,
    remaining_work: &usize,
) -> Result<(), DcqlError> {
    reserve_comparisons(pending, 1, remaining_work)?;
    pending.push((expected, actual));
    Ok(())
}

fn reserve_comparisons(
    pending: &mut Vec<(&JsonValue, &JsonValue)>,
    additional: usize,
    remaining_work: &usize,
) -> Result<(), DcqlError> {
    let required = pending
        .len()
        .checked_add(additional)
        .ok_or_else(|| DcqlError::new(DcqlErrorReason::QueryTooLarge))?;
    // Refuse attacker-controlled fan-out before reserving memory. Every
    // pending node will consume at least one unit, so a larger stack cannot
    // complete within the remaining evaluation budget.
    if required > *remaining_work {
        return Err(DcqlError::new(DcqlErrorReason::QueryTooLarge));
    }
    pending
        .try_reserve(additional)
        .map_err(|_| DcqlError::new(DcqlErrorReason::QueryTooLarge))
}

#[cfg(test)]
#[path = "evaluate_metadata_tests.rs"]
mod tests;
