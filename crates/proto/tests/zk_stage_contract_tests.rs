// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks the stable stage tags and the additive artifact-set digest.
#![cfg(feature = "generated")]
#![allow(missing_docs)]

use buffa::Message;
use reallyme_openid4vp_proto::generated::proto::reallyme::openid4vp::v1::ZkPresentationStage;

#[test]
fn manifest_stage_keeps_its_v1_wire_tags() -> Result<(), buffa::DecodeError> {
    let mut wire = vec![0x1a, 32];
    wire.extend_from_slice(&[5; 32]);
    wire.extend_from_slice(&[0x22, 2, 0xa1, 0xa2, 0x2a, 2, 0xb1, 0xb2]);

    let stage = ZkPresentationStage::decode_from_slice(&wire)?;
    assert_eq!(stage.artifact_manifest_sha256, [5; 32]);
    assert_eq!(stage.artifact_set_identity_sha256, None);
    assert_eq!(stage.proof, [0xa1, 0xa2]);
    assert_eq!(stage.public_inputs, [0xb1, 0xb2]);
    assert_eq!(stage.encode_to_vec(), wire);
    let hex: String = wire.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        include_str!("fixtures/zk-stage-manifest.pb.hex").trim()
    );
    Ok(())
}

#[test]
fn artifact_set_stage_uses_the_new_tag() -> Result<(), buffa::DecodeError> {
    let mut wire = vec![0x22, 2, 0xa1, 0xa2, 0x2a, 2, 0xb1, 0xb2, 0x32, 32];
    wire.extend_from_slice(&[7; 32]);

    let stage = ZkPresentationStage::decode_from_slice(&wire)?;
    assert!(stage.artifact_manifest_sha256.is_empty());
    assert_eq!(
        stage.artifact_set_identity_sha256.as_deref(),
        Some([7; 32].as_slice())
    );
    assert_eq!(stage.proof, [0xa1, 0xa2]);
    assert_eq!(stage.public_inputs, [0xb1, 0xb2]);
    assert_eq!(stage.encode_to_vec(), wire);
    let hex: String = wire.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        include_str!("fixtures/zk-stage-artifact-set.pb.hex").trim()
    );

    wire.pop();
    assert!(ZkPresentationStage::decode_from_slice(&wire).is_err());
    Ok(())
}
