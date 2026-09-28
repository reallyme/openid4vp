// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::zeroize_json::zeroize_json_value;

/// Raw verifier metadata carried inline or resolved by client identifier rules.
///
/// OpenID4VP 1.0 defines `vp_formats_supported` as an object whose values are
/// format-specific parameter objects. Keeping the extension-friendly protocol
/// object intact avoids publishing a lossy DTO that silently changes those
/// shapes or invents non-standard capability members.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientMetadata {
    /// Exact metadata JSON object.
    pub raw: JsonValue,
}

impl fmt::Debug for ClientMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientMetadata(<redacted>)")
    }
}

impl Zeroize for ClientMetadata {
    fn zeroize(&mut self) {
        zeroize_json_value(&mut self.raw);
    }
}

impl Drop for ClientMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ClientMetadata {}

#[cfg(test)]
#[path = "define_metadata_tests.rs"]
mod tests;
