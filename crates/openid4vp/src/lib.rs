// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public facade for ReallyMe OpenID4VP crates.
//!
//! Generated protobuf messages and ProtoJSON are the SDK DTO contract. The
//! re-exported Rust domain crates provide native validation and policy APIs;
//! their Serde implementations are not cross-language compatibility surfaces.

#[path = "configure_policy.rs"]
pub mod policy;
#[cfg(feature = "codec")]
pub mod sdk;

#[cfg(feature = "dc-api")]
pub use reallyme_openid4vp_dc_api as dc_api;
pub use reallyme_openid4vp_dcql as dcql;
#[cfg(feature = "formats")]
pub use reallyme_openid4vp_formats as formats;
#[cfg(feature = "http")]
pub use reallyme_openid4vp_http as http;
#[cfg(feature = "profiles")]
pub use reallyme_openid4vp_profiles as profiles;
#[cfg(feature = "runtime")]
pub use reallyme_openid4vp_runtime as runtime;
pub use reallyme_openid4vp_types as types;
pub use reallyme_openid4vp_verifier as verifier;
pub use reallyme_openid4vp_wallet as wallet;
