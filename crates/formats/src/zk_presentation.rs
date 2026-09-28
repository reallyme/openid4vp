// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_types::PresentationValue;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::report_zk_error::{ZkFormatError, ZkFormatErrorReason};

#[path = "zk_presentation_types.rs"]
mod types;
#[path = "zk_presentation_validation.rs"]
mod validation;

pub use types::{
    DerivedClaimStatement, ZkPresentation, ZkPresentationBinding, ZkPresentationCircuitRef,
    ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage, ZkPresentationStageKind,
};
pub use validation::{validate_zk_presentation_binding, validate_zk_presentation_shape};

/// ZK presentation marker used inside JSON-native `vp_token` entries.
pub const ZK_PRESENTATION_TYPE: &str = "reallyme.openid4vp.zk_presentation.v1";

/// Maximum proof bytes accepted before invoking an external ZK verifier.
pub const MAX_ZK_PRESENTATION_PROOF_BYTES: usize = 16 * 1024 * 1024;
/// Maximum public-input bytes accepted before invoking an external ZK verifier.
pub const MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES: usize = 1024 * 1024;
/// Maximum derived claims accepted in one ZK presentation.
pub const MAX_ZK_PRESENTATION_DERIVED_CLAIMS: usize = 256;
/// Maximum bytes accepted for a derived-claim statement identifier.
pub const MAX_ZK_STATEMENT_ID_BYTES: usize = 256;
/// Maximum bytes accepted for a derived-claim semantic label.
pub const MAX_ZK_STATEMENT_BYTES: usize = 1024;
/// Maximum bytes accepted for a circuit identifier or circuit-ref label.
pub const MAX_ZK_CIRCUIT_LABEL_BYTES: usize = 256;
/// Exact number of stages in the production proof-bundle contract.
pub const ZK_PRESENTATION_STAGE_COUNT: usize = 4;

/// Validate and encode an externally produced ZK envelope as a `vp_token` value.
///
/// ZK proving belongs to the composed wallet or service. This function keeps
/// OpenID4VP responsible for its wire contract without importing a particular
/// circuit registry, witness model, or proving backend.
pub fn encode_zk_presentation_value(
    presentation: ZkPresentation,
) -> Result<PresentationValue, ZkFormatError> {
    validate_zk_presentation_shape(&presentation)?;
    let value = serde_json::to_value(presentation)
        .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))?;
    Ok(PresentationValue::Json(value))
}

/// Parse a `vp_token` presentation value as a ZK presentation when marked.
pub fn parse_zk_presentation_value(
    value: &PresentationValue,
) -> Result<Option<ZkPresentation>, ZkFormatError> {
    let PresentationValue::Json(json) = value else {
        return Ok(None);
    };
    if json
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_none_or(|value| value != ZK_PRESENTATION_TYPE)
    {
        return Ok(None);
    }
    let presentation = ZkPresentation::deserialize(json)
        .map_err(|_| ZkFormatError::new(ZkFormatErrorReason::InvalidPresentationEncoding))?;
    validate_zk_presentation_shape(&presentation)?;
    Ok(Some(presentation))
}

/// Return whether a presentation value is marked as a ReallyMe ZK presentation.
pub fn is_zk_presentation_value(value: &PresentationValue) -> bool {
    let PresentationValue::Json(json) = value else {
        return false;
    };
    json.get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value == ZK_PRESENTATION_TYPE)
}

/// Build the session-binding hashes required in a ZK presentation envelope.
#[must_use]
pub fn build_zk_presentation_binding(
    nonce: &str,
    audience: &str,
    transaction_data_hash: Option<[u8; 32]>,
) -> ZkPresentationBinding {
    ZkPresentationBinding {
        nonce_hash: hash_openid4vp_nonce(nonce),
        audience_hash: hash_openid4vp_audience(audience),
        transaction_data_hash,
    }
}

/// Hash an OpenID4VP nonce for ZK public-input binding.
#[must_use]
pub fn hash_openid4vp_nonce(nonce: &str) -> [u8; 32] {
    sha256_bytes(nonce.as_bytes())
}

/// Hash an OpenID4VP verifier audience for ZK public-input binding.
#[must_use]
pub fn hash_openid4vp_audience(audience: &str) -> [u8; 32] {
    sha256_bytes(audience.as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
#[path = "zk_presentation_tests.rs"]
mod tests;
