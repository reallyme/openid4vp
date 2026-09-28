// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{RuntimeError, RuntimeErrorReason};

const MAX_FORM_URLENCODED_PAIRS: usize = 64;
const MAX_FORM_KEY_BYTES: usize = 256;
const MAX_FORM_VALUE_BYTES: usize = 64 * 1024;

/// One decoded application/x-www-form-urlencoded pair.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FormPair {
    pub(crate) key: String,
    pub(crate) value: String,
}

impl fmt::Debug for FormPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormPair")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for FormPair {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.value.zeroize();
    }
}

impl Drop for FormPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for FormPair {}

pub(crate) fn parse_form_urlencoded(body: &[u8]) -> Result<Vec<FormPair>, RuntimeError> {
    if body.is_empty() {
        return Ok(Vec::new());
    }

    let mut pairs = Vec::new();
    for raw_pair in body.split(|byte| *byte == b'&') {
        if raw_pair.is_empty() {
            continue;
        }
        if pairs.len() >= MAX_FORM_URLENCODED_PAIRS {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
        }
        let mut split = raw_pair.splitn(2, |byte| *byte == b'=');
        let Some(raw_key) = split.next() else {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
        };
        let raw_value = match split.next() {
            Some(value) => value,
            None => &[],
        };
        if raw_key.is_empty()
            || raw_key.len() > MAX_FORM_KEY_BYTES
            || raw_value.len() > MAX_FORM_VALUE_BYTES
        {
            return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
        }
        pairs.push(FormPair {
            key: decode_form_component(raw_key)?,
            value: decode_form_component(raw_value)?,
        });
    }
    Ok(pairs)
}

pub(crate) fn required_unique_field<'a>(
    pairs: &'a [FormPair],
    key: &str,
) -> Result<&'a str, RuntimeError> {
    let mut found: Option<&str> = None;
    for pair in pairs {
        if pair.key != key {
            continue;
        }
        if found.is_some() {
            return Err(RuntimeError::new(RuntimeErrorReason::DuplicateFormField));
        }
        found = Some(&pair.value);
    }
    let Some(value) = found else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingFormField));
    };
    Ok(value)
}

pub(crate) fn optional_unique_field<'a>(
    pairs: &'a [FormPair],
    key: &str,
) -> Result<Option<&'a str>, RuntimeError> {
    let mut found: Option<&str> = None;
    for pair in pairs {
        if pair.key != key {
            continue;
        }
        if found.is_some() {
            return Err(RuntimeError::new(RuntimeErrorReason::DuplicateFormField));
        }
        found = Some(&pair.value);
    }
    Ok(found)
}

fn decode_form_component(bytes: &[u8]) -> Result<String, RuntimeError> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index = checked_advance(index, 1)?;
            }
            b'%' => {
                let high_index = checked_advance(index, 1)?;
                let low_index = checked_advance(index, 2)?;
                if low_index >= bytes.len() {
                    return Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody));
                }
                let high = hex_value(bytes[high_index])?;
                let low = hex_value(bytes[low_index])?;
                decoded.push((high << 4) | low);
                index = checked_advance(index, 3)?;
            }
            byte => {
                decoded.push(byte);
                index = checked_advance(index, 1)?;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| RuntimeError::new(RuntimeErrorReason::InvalidFormBody))
}

fn checked_advance(index: usize, amount: usize) -> Result<usize, RuntimeError> {
    index
        .checked_add(amount)
        .ok_or(RuntimeError::new(RuntimeErrorReason::InvalidFormBody))
}

fn hex_value(byte: u8) -> Result<u8, RuntimeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RuntimeError::new(RuntimeErrorReason::InvalidFormBody)),
    }
}
