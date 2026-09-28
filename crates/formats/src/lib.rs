// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Format-specific presentation glue for SD-JWT VC, mdoc, and W3C VC.
//!
//! Serde implementations in this crate exist only for bounded internal
//! protocol parsing of format-native presentation values. They are not stable
//! SDK DTO contracts. Cross-language and SDK boundaries must use generated
//! OpenID4VP protobuf messages and validated canonical JSON byte fields.

mod define_formats;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod mdoc;
#[cfg(any(feature = "native", feature = "wasm"))]
mod parse_transaction_data_binding;
mod report_zk_error;
#[cfg(any(feature = "native", feature = "wasm"))]
pub mod sd_jwt;
#[cfg(any(feature = "native", feature = "wasm"))]
mod sd_jwt_error;
#[cfg(any(feature = "native", feature = "wasm"))]
mod zeroize_json;
mod zk_presentation;

pub use define_formats::{FORMAT_DC_SD_JWT, FORMAT_MSO_MDOC, FORMAT_REALLYME_ZK};
pub use report_zk_error::{ZkFormatError, ZkFormatErrorReason};
pub use zk_presentation::{
    build_zk_presentation_binding, encode_zk_presentation_value, hash_openid4vp_audience,
    hash_openid4vp_nonce, is_zk_presentation_value, parse_zk_presentation_value,
    validate_zk_presentation_binding, validate_zk_presentation_shape, DerivedClaimStatement,
    ZkPresentation, ZkPresentationBinding, ZkPresentationCircuitRef, ZkPresentationProfile,
    ZkPresentationProofSuite, ZkPresentationStage, ZkPresentationStageKind,
    MAX_ZK_CIRCUIT_LABEL_BYTES, MAX_ZK_PRESENTATION_DERIVED_CLAIMS,
    MAX_ZK_PRESENTATION_PROOF_BYTES, MAX_ZK_PRESENTATION_PUBLIC_INPUT_BYTES,
    MAX_ZK_STATEMENT_BYTES, MAX_ZK_STATEMENT_ID_BYTES, ZK_PRESENTATION_STAGE_COUNT,
    ZK_PRESENTATION_TYPE,
};
