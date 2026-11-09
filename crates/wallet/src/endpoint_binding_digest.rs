// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixed-size certificate identity and timing-safe digest comparison.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub(super) fn sha256_array(value: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(value);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub(super) fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}
