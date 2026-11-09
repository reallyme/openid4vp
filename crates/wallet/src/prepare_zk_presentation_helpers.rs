// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::{WalletError, WalletErrorReason};

const CLAIM_HASH_HEX_BYTES: usize = 64;

pub(crate) fn parse_lower_hex_hash(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != CLAIM_HASH_HEX_BYTES {
        return None;
    }
    let mut hash = [0_u8; 32];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (index, pair) in pairs.iter().enumerate() {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        hash[index] = (high << 4) | low;
    }
    Some(hash)
}

const fn lower_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub(super) fn copy_bounded(bytes: &[u8]) -> Result<Vec<u8>, WalletError> {
    let mut copied = Vec::new();
    copied
        .try_reserve_exact(bytes.len())
        .map_err(|_| zk_error())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

pub(super) const fn zk_error() -> WalletError {
    WalletError::new(WalletErrorReason::ZkDerivationFailed)
}
