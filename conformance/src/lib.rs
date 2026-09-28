// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Machine-readable OpenID4VP conformance vector harness.

pub mod error;
pub mod parse;
pub mod run;
pub mod strict_json;
pub mod vector;

pub use error::{ConformanceError, ConformanceResult};
pub use parse::parse_vectors;
pub use run::{run_vector, run_vectors, VectorOutcome};
pub use strict_json::validate_strict_json;
pub use vector::{ConformanceVector, ExpectedResult};
