// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_types::ClientIdentifier;

use crate::mdoc::{
    build_dc_api_handover_digest, build_dc_api_session_transcript,
    build_redirect_session_transcript, CanonicalMdocHandoverCborEncoder, EncodedHandoverInfo,
    HandoverDigestInput, HandoverKind, MdocHandoverCborEncoder, OpenId4VpDcApiHandover,
    OpenId4VpRedirectHandover, MAX_MDOC_HANDOVER_TEXT_BYTES, SHA256_DIGEST_BYTES,
};
use crate::{DcApiError, DcApiErrorReason};

const EXAMPLE_NONCE: &str = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA";
const EXAMPLE_THUMBPRINT_HEX: &str =
    "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047";

struct FixtureEncoder;

impl MdocHandoverCborEncoder for FixtureEncoder {
    fn encode_handover_info(
        &self,
        input: &HandoverDigestInput,
    ) -> Result<EncodedHandoverInfo, DcApiError> {
        let marker = match input {
            HandoverDigestInput::Redirect(_) => vec![0x01],
            HandoverDigestInput::DigitalCredentialsApi(_) => vec![0x02],
        };
        EncodedHandoverInfo::new(marker)
    }
}

#[test]
fn computes_digest_from_delegated_handover_bytes() {
    let digest = build_dc_api_handover_digest(
        OpenId4VpDcApiHandover {
            origin: "https://rp.example".to_owned(),
            nonce: "0123456789abcdef".to_owned(),
            jwk_thumbprint_sha256: None,
        },
        &FixtureEncoder,
    )
    .expect("fixture handover encodes");

    assert_eq!(digest.kind, HandoverKind::DigitalCredentialsApi);
    assert_eq!(digest.digest.len(), SHA256_DIGEST_BYTES);
}

#[test]
fn canonical_redirect_matches_final_specification_vectors() {
    let input = redirect_example();
    let encoded = CanonicalMdocHandoverCborEncoder
        .encode_handover_info(&HandoverDigestInput::Redirect(input.clone()))
        .expect("official redirect vector encodes");
    assert_eq!(
        encoded.as_bytes(),
        decode_hex(concat!(
            "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b6578633767",
            "426b786a7831726463397564527276654b7653734a4971383061766c58654c486847",
            "7771744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6",
            "bd669047781c68747470733a2f2f6578616d706c652e636f6d2f726573706f6e7365"
        ))
    );

    let transcript = build_redirect_session_transcript(input, &CanonicalMdocHandoverCborEncoder)
        .expect("official redirect transcript encodes");
    assert_eq!(
        transcript.as_bytes(),
        decode_hex(concat!(
            "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e",
            "ed494cefdd9d95240d254b046b11b68013722aad38ac"
        ))
    );
}

#[test]
fn canonical_dc_api_matches_final_specification_vectors() {
    let input = OpenId4VpDcApiHandover {
        origin: "https://example.com".to_owned(),
        nonce: EXAMPLE_NONCE.to_owned(),
        jwk_thumbprint_sha256: Some(example_thumbprint()),
    };
    let encoded = CanonicalMdocHandoverCborEncoder
        .encode_handover_info(&HandoverDigestInput::DigitalCredentialsApi(input.clone()))
        .expect("official DC API vector encodes");
    assert_eq!(
        encoded.as_bytes(),
        decode_hex(concat!(
            "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b786a7831",
            "726463397564527276654b7653734a4971383061766c58654c486847777174415820",
            "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"
        ))
    );

    let transcript = build_dc_api_session_transcript(input, &CanonicalMdocHandoverCborEncoder)
        .expect("official DC API transcript encodes");
    assert_eq!(
        transcript.as_bytes(),
        decode_hex(concat!(
            "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4",
            "212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
        ))
    );
}

#[test]
fn canonical_redirect_encodes_null_without_response_encryption() {
    let mut input = redirect_example();
    input.jwk_thumbprint_sha256 = None;
    let encoded = CanonicalMdocHandoverCborEncoder
        .encode_handover_info(&HandoverDigestInput::Redirect(input))
        .expect("unencrypted redirect handover encodes");

    assert!(encoded
        .as_bytes()
        .windows(2)
        .any(|bytes| bytes == [0xf6, 0x78]));
}

#[test]
fn rejects_oversized_handover_text_before_encoding() {
    let error = CanonicalMdocHandoverCborEncoder
        .encode_handover_info(&HandoverDigestInput::DigitalCredentialsApi(
            OpenId4VpDcApiHandover {
                origin: "a".repeat(MAX_MDOC_HANDOVER_TEXT_BYTES + 1),
                nonce: "0123456789abcdef".to_owned(),
                jwk_thumbprint_sha256: None,
            },
        ))
        .expect_err("oversized origin must be rejected");

    assert_eq!(error.reason(), DcApiErrorReason::HandoverValueTooLarge);
}

#[test]
fn sensitive_handover_debug_output_is_redacted() {
    let input = redirect_example();
    let debug = format!("{input:?}");

    assert!(!debug.contains(EXAMPLE_NONCE));
    assert!(!debug.contains("https://example.com/response"));
    assert!(debug.contains("<redacted>"));
}

fn redirect_example() -> OpenId4VpRedirectHandover {
    OpenId4VpRedirectHandover {
        client_id: ClientIdentifier::parse("x509_san_dns:example.com")
            .expect("official client identifier parses"),
        nonce: EXAMPLE_NONCE.to_owned(),
        jwk_thumbprint_sha256: Some(example_thumbprint()),
        response_uri: "https://example.com/response".to_owned(),
    }
}

fn example_thumbprint() -> [u8; SHA256_DIGEST_BYTES] {
    decode_hex(EXAMPLE_THUMBPRINT_HEX)
        .try_into()
        .expect("official thumbprint has SHA-256 length")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex fixture must have even length");
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = core::str::from_utf8(pair).expect("hex fixture must be UTF-8");
            u8::from_str_radix(digits, 16).expect("hex fixture must contain hex digits")
        })
        .collect()
}
