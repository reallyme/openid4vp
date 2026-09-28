// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_formats::{encode_zk_presentation_value, ZkPresentation};
use reallyme_openid4vp_types::PresentationValue;

use crate::{WalletError, WalletErrorReason};

/// Validate an externally produced ZK envelope for inclusion in a response.
///
/// The composed wallet owns credential selection, witness construction, and
/// proof generation. This boundary deliberately accepts only the resulting
/// backend-neutral OpenID4VP envelope.
pub fn prepare_zk_presentation(
    presentation: ZkPresentation,
) -> Result<PresentationValue, WalletError> {
    encode_zk_presentation_value(presentation)
        .map_err(|_| WalletError::new(WalletErrorReason::ZkDerivationFailed))
}

#[cfg(test)]
#[path = "prepare_zk_presentation_tests.rs"]
mod tests;
