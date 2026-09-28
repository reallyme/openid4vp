// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_crypto::{
    core::{CryptoError, RngOutputKind},
    csprng::SecureRandom,
};

use super::{ResponseCode, RESPONSE_CODE_RANDOM_BYTES};

struct FixedRandom;

impl SecureRandom for FixedRandom {
    fn fill_secure(&mut self, output: &mut [u8], _kind: RngOutputKind) -> Result<(), CryptoError> {
        output.fill(7);
        Ok(())
    }
}

#[test]
fn response_code_requires_a_bounded_base64url_value() {
    assert!(ResponseCode::parse("short".to_owned()).is_err());
    assert!(ResponseCode::parse("0123456789abcdef01234=".to_owned()).is_err());
    assert!(ResponseCode::parse("0123456789abcdef01234/".to_owned()).is_err());

    let code = ResponseCode::parse("0123456789abcdef012345".to_owned())
        .expect("test response code is valid");
    assert_eq!(code.as_str(), "0123456789abcdef012345");
    assert!(!format!("{code:?}").contains(code.as_str()));
}

#[test]
fn response_code_is_generated_from_256_bits_of_injected_secure_randomness() {
    let code = ResponseCode::generate_with_rng(&mut FixedRandom)
        .expect("fixed secure random source generates a response code");

    assert_eq!(
        code.as_str().len(),
        (RESPONSE_CODE_RANDOM_BYTES * 4).div_ceil(3)
    );
    assert!(code
        .as_str()
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
}
