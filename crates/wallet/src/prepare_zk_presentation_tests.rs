// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use reallyme_openid4vp_dcql::{CredentialFormat, CredentialQuery, DcqlQuery, QueryId};
use reallyme_openid4vp_formats::{
    build_zk_presentation_binding, parse_zk_presentation_value, ZkPresentation,
    ZkPresentationCircuitRef, ZkPresentationProfile, ZkPresentationProofSuite, ZkPresentationStage,
    ZkPresentationStageKind, ZK_PRESENTATION_TYPE,
};
use reallyme_openid4vp_types::{
    AuthorizationRequestObject, ClientIdentifier, ResponseMode, ResponseType, TransactionData,
    TransactionDataHash,
};
use reallyme_zk_api::{
    ZkArtifactManifestDigest, ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage,
    ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRawPublicInputs,
    ZkCommonCredentialRootV1Profile, ZkHashStrategy, ZkIssuerCredentialStatusProof,
    ZkProductionStage, ZkProof, ZkProofBundle, ZkProofBytes, ZkProofProfile, ZkProofSuite,
    ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs, ZkSessionBinding, ZkStageProof,
    ZkStatusQualifiedBundle,
};
use serde_json::json;

use super::{
    prepare_zk_presentation, prepare_zk_presentation_from_bundle,
    prepare_zk_presentation_from_common_credential_root,
    prepare_zk_presentation_from_status_qualified_bundle, WalletCommonCredentialRootPresentation,
    WalletCommonCredentialRootProof,
};
use crate::{
    VerifiedWalletRequest, WalletAuthorizationRequest, WalletErrorReason, WalletInvocationContext,
};

#[test]
fn prepares_an_externally_produced_zk_envelope() {
    let value = prepare_zk_presentation(presentation_fixture())
        .expect("valid external envelope is accepted");
    assert!(parse_zk_presentation_value(&value)
        .expect("prepared value parses")
        .is_some());
}

#[test]
fn rejects_an_invalid_external_zk_envelope() {
    let mut presentation = presentation_fixture();
    presentation.stages[0].proof.clear();

    let error = prepare_zk_presentation(presentation)
        .expect_err("empty proof material must fail before response construction");
    assert_eq!(error.reason(), WalletErrorReason::ZkDerivationFailed);
}

fn presentation_fixture() -> ZkPresentation {
    let stages = [
        (ZkPresentationStageKind::Session, "session"),
        (
            ZkPresentationStageKind::CredentialEnvelope,
            "credential_envelope",
        ),
        (ZkPresentationStageKind::CredentialRoot, "credential_root"),
        (ZkPresentationStageKind::Claim, "claim"),
    ]
    .into_iter()
    .map(|(stage, stage_name)| ZkPresentationStage {
        stage,
        circuit_ref: ZkPresentationCircuitRef {
            hash_strategy: "sha256".to_owned(),
            family: "credential_subject_claim_v1".to_owned(),
            stage: stage_name.to_owned(),
            version: 1,
        },
        artifact_manifest_sha256: [3_u8; 32],
        proof: vec![4_u8],
        public_inputs: vec![5_u8],
    })
    .collect();
    ZkPresentation {
        type_: ZK_PRESENTATION_TYPE.to_owned(),
        profile: ZkPresentationProfile::CredentialSubjectClaimV1,
        proof_suite: ZkPresentationProofSuite::BarretenbergUltraHonkKeccakZkNoIpa,
        stages,
        derived_claims: Vec::new(),
        binding: build_zk_presentation_binding(
            "0123456789abcdef",
            "x509_san_dns:verifier.example",
            None,
        ),
    }
}

fn verified_request(transaction_data: bool) -> VerifiedWalletRequest {
    let meta = json!({
        "profile": "credential_subject_claim_v1",
        "hash_strategy": "sha256",
        "claim_name_hash": "0303030303030303030303030303030303030303030303030303030303030303",
        "claim_value_b64u": "CQ"
    })
    .as_object()
    .expect("test query metadata is an object")
    .clone();
    VerifiedWalletRequest::for_test(AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta,
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        transaction_data: transaction_data.then(|| {
            vec![TransactionData::new(
                "urn:example:transaction".to_owned(),
                vec!["pid".to_owned()],
                json!({"amount": 1}),
            )
            .expect("test transaction data is valid")]
        }),
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    })
}

fn verified_common_credential_root_request(transaction_data: bool) -> VerifiedWalletRequest {
    let meta = json!({
        "profile": "common_credential_root_v1_private_persona",
        "hash_strategy": "sha256",
        "claim_0_name_hash": "0303030303030303030303030303030303030303030303030303030303030303",
        "claim_0_value_b64u": "CQ",
        "claim_1_name_hash": "0404040404040404040404040404040404040404040404040404040404040404",
        "claim_1_value_b64u": "Cg"
    })
    .as_object()
    .expect("test query metadata is an object")
    .clone();
    VerifiedWalletRequest::for_test(AuthorizationRequestObject {
        client_id: Some(
            ClientIdentifier::parse("x509_san_dns:verifier.example")
                .expect("test client id is valid"),
        ),
        response_type: ResponseType::VpToken,
        response_mode: Some(ResponseMode::DirectPost),
        response_uri: Some("https://verifier.example/response".to_owned()),
        redirect_uri: None,
        nonce: "0123456789abcdef".to_owned(),
        wallet_nonce: None,
        state: None,
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: QueryId::parse("pid").expect("test query id is valid"),
                format: CredentialFormat::new(CredentialFormat::REALLYME_ZK_V1.to_owned())
                    .expect("test format is valid"),
                multiple: false,
                meta,
                trusted_authorities: None,
                require_cryptographic_holder_binding: true,
                claims: None,
                claim_sets: None,
            }],
            credential_sets: None,
        },
        transaction_data: transaction_data.then(|| {
            vec![TransactionData::new(
                "urn:example:transaction".to_owned(),
                vec!["pid".to_owned()],
                json!({"amount": 1}),
            )
            .expect("test transaction data is valid")]
        }),
        client_metadata: None,
        client_metadata_uri: None,
        verifier_info: None,
        expected_origins: None,
        iss: None,
        aud: None,
        iat: None,
        exp: None,
    })
}

fn write_field(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) {
    let range = descriptor.field_range(name).expect("test ABI field exists");
    bytes[range].copy_from_slice(value);
}

#[allow(clippy::panic)]
fn fixture_public_inputs(circuit: ZkCircuitRef, binding: ZkSessionBinding) -> ZkPublicInputs {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit).expect("test ABI exists");
    let mut bytes = vec![0_u8; descriptor.encoded_len().expect("test ABI is bounded")];
    for field in descriptor.fields() {
        match field.name {
            ZkPublicInputName::Challenge => {
                write_field(&mut bytes, descriptor, field.name, &binding.nonce_hash)
            }
            ZkPublicInputName::AudienceHash => {
                write_field(&mut bytes, descriptor, field.name, &binding.audience_hash)
            }
            ZkPublicInputName::TransactionDataHash => write_field(
                &mut bytes,
                descriptor,
                field.name,
                &binding.transaction_data_public_input(),
            ),
            ZkPublicInputName::ExpiryUnix => {
                write_field(&mut bytes, descriptor, field.name, &20_u64.to_be_bytes())
            }
            ZkPublicInputName::SessionBinding => {
                write_field(&mut bytes, descriptor, field.name, &[12_u8; 32])
            }
            ZkPublicInputName::EnvelopeBinding => {
                write_field(&mut bytes, descriptor, field.name, &[13_u8; 32])
            }
            ZkPublicInputName::CredentialBinding => {
                write_field(&mut bytes, descriptor, field.name, &[14_u8; 32])
            }
            ZkPublicInputName::ClaimNameHash => {
                write_field(&mut bytes, descriptor, field.name, &[3_u8; 32])
            }
            ZkPublicInputName::ValueLength => {
                write_field(&mut bytes, descriptor, field.name, &1_u32.to_be_bytes())
            }
            ZkPublicInputName::Value => {
                let mut value = [0_u8; 64];
                value[0] = 9;
                write_field(&mut bytes, descriptor, field.name, &value);
            }
            ZkPublicInputName::IssuerPublicKeyX | ZkPublicInputName::IssuerPublicKeyY => {}
            _ => panic!("test fixture contains only production fields"),
        }
    }
    ZkPublicInputs::try_from_bytes(bytes).expect("test public inputs are bounded")
}

fn bundle(transaction_data_hash: Option<[u8; 32]>) -> ZkProofBundle {
    bundle_for("x509_san_dns:verifier.example", transaction_data_hash)
}

fn bundle_for(audience: &str, transaction_data_hash: Option<[u8; 32]>) -> ZkProofBundle {
    let expected =
        build_zk_presentation_binding("0123456789abcdef", audience, transaction_data_hash);
    let binding = ZkSessionBinding {
        nonce_hash: expected.nonce_hash,
        audience_hash: expected.audience_hash,
        transaction_data_hash,
    };
    let stages = ZkProductionStage::ALL
        .iter()
        .map(|stage| {
            let circuit =
                ZkProofProfile::CredentialSubjectClaimV1.source_ref(ZkHashStrategy::Sha256, *stage);
            let proof = ZkProof::try_from_exact_parts(
                ZkProofProfile::CredentialSubjectClaimV1.circuit_id(),
                circuit,
                ZkProofSuite::PRODUCTION,
                ZkArtifactManifestDigest::from_bytes([7_u8; 32]),
                vec![stage.index() + 1],
                fixture_public_inputs(circuit, binding),
            )
            .expect("test stage proof is well formed");
            ZkStageProof::try_from_parts(ZkProofProfile::CredentialSubjectClaimV1, *stage, proof)
                .expect("test stage matches profile")
        })
        .collect();
    ZkProofBundle::try_from_stage_proofs(ZkProofProfile::CredentialSubjectClaimV1, binding, stages)
        .expect("test bundle is structurally complete")
}

fn status_qualified_bundle() -> ZkStatusQualifiedBundle {
    let claim_bundle = bundle(None);
    let statement = claim_bundle
        .decode_claimed_statement()
        .expect("test bundle has a claim");
    let binding = claim_bundle.session_binding();
    let circuit_ref = ZkCircuitRef::new(
        ZkHashStrategy::Sha256,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    let mut raw = vec![0_u8; 292 * 32];
    set_common_credential_root_request(&mut raw, 0, binding);
    set_common_credential_root_bytes32(&mut raw, 96, &statement.issuer().x);
    set_common_credential_root_bytes32(&mut raw, 128, &statement.issuer().y);
    set_common_credential_root_u64(&mut raw, 160, statement.presentation_expiry_unix());
    set_common_credential_root_bytes32(&mut raw, 161, &statement.credential_binding());
    set_common_credential_root_bytes32(&mut raw, 193, &[0x41; 32]);
    set_common_credential_root_u64(&mut raw, 225, 256);
    set_common_credential_root_bytes32(&mut raw, 226, &[0x42; 32]);
    set_common_credential_root_bytes32(&mut raw, 258, &[0x43; 32]);
    raw[290 * 32 + 31] = 1;
    set_common_credential_root_u64(&mut raw, 291, 10);
    let inputs = ZkCommonCredentialRootRawPublicInputs::try_from_bytes(circuit_ref, raw)
        .expect("status proof follows the source ABI");
    let status = ZkIssuerCredentialStatusProof::try_from_parts(
        ZkProofSuite::PRODUCTION,
        ZkArtifactManifestDigest::from_bytes([7; 32]),
        ZkProofBytes::try_copy_from_slice(&[5]).expect("fixture proof bytes are bounded"),
        inputs,
    )
    .expect("status proof has the pinned source");
    ZkStatusQualifiedBundle::try_from_parts(claim_bundle, status)
        .expect("status joins to the selected credential")
}

#[test]
fn serializes_status_qualified_claim_for_verified_request() {
    let request = verified_request(false);
    let value = prepare_zk_presentation_from_status_qualified_bundle(
        &request,
        &WalletInvocationContext::ProtocolTransport,
        &QueryId::parse("pid").expect("test query id is valid"),
        &status_qualified_bundle(),
    )
    .expect("matching claim and issuer status are encoded together");
    let parsed = parse_zk_presentation_value(&value)
        .expect("wire value parses")
        .expect("wire value is a ZK presentation");
    assert_eq!(parsed.stages.len(), 5);
    assert_eq!(
        parsed.stages[4].stage,
        ZkPresentationStageKind::IssuerCredentialStatus,
    );
}

struct CommonCredentialRootProofFixture {
    slot: ZkCommonCredentialRootProofSlot,
    artifact_manifest_sha256: ZkArtifactManifestDigest,
    proof_bytes: ZkProofBytes,
    public_inputs: ZkCommonCredentialRootRawPublicInputs,
}

impl WalletCommonCredentialRootProof for CommonCredentialRootProofFixture {
    fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.slot
    }

    fn artifact_manifest_sha256(&self) -> ZkArtifactManifestDigest {
        self.artifact_manifest_sha256
    }

    fn proof_bytes(&self) -> &ZkProofBytes {
        &self.proof_bytes
    }

    fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        &self.public_inputs
    }
}

struct CommonCredentialRootPresentationFixture {
    profile: ZkCommonCredentialRootV1Profile,
    hash_strategy: ZkHashStrategy,
    proof_suite: ZkProofSuite,
    binding: ZkSessionBinding,
    proofs: Vec<CommonCredentialRootProofFixture>,
}

impl WalletCommonCredentialRootPresentation for CommonCredentialRootPresentationFixture {
    type Proof = CommonCredentialRootProofFixture;

    fn profile(&self) -> ZkCommonCredentialRootV1Profile {
        self.profile
    }

    fn hash_strategy(&self) -> ZkHashStrategy {
        self.hash_strategy
    }

    fn proof_suite(&self) -> ZkProofSuite {
        self.proof_suite
    }

    fn session_binding(&self) -> ZkSessionBinding {
        self.binding
    }

    fn proofs(&self) -> &[Self::Proof] {
        &self.proofs
    }
}

fn common_credential_root_presentation(
    transaction_data_hash: Option<[u8; 32]>,
) -> CommonCredentialRootPresentationFixture {
    common_credential_root_presentation_for("x509_san_dns:verifier.example", transaction_data_hash)
}

fn common_credential_root_presentation_for(
    audience: &str,
    transaction_data_hash: Option<[u8; 32]>,
) -> CommonCredentialRootPresentationFixture {
    let expected =
        build_zk_presentation_binding("0123456789abcdef", audience, transaction_data_hash);
    let binding = ZkSessionBinding {
        nonce_hash: expected.nonce_hash,
        audience_hash: expected.audience_hash,
        transaction_data_hash,
    };
    let profile = ZkCommonCredentialRootV1Profile::PrivatePersona;
    let hash_strategy = ZkHashStrategy::Sha256;
    let proofs = ZkCommonCredentialRootProofSlot::ALL
        .iter()
        .map(|slot| {
            let circuit_ref = profile.source_ref(hash_strategy, *slot);
            CommonCredentialRootProofFixture {
                slot: *slot,
                artifact_manifest_sha256: ZkArtifactManifestDigest::from_bytes([0x77; 32]),
                proof_bytes: ZkProofBytes::try_copy_from_slice(&[slot.index() + 1])
                    .expect("test proof bytes are bounded"),
                public_inputs: ZkCommonCredentialRootRawPublicInputs::try_from_bytes(
                    circuit_ref,
                    common_credential_root_raw_inputs(circuit_ref, *slot, binding),
                )
                .expect("test common-credential-root public inputs are valid"),
            }
        })
        .collect();
    CommonCredentialRootPresentationFixture {
        profile,
        hash_strategy,
        proof_suite: ZkProofSuite::PRODUCTION,
        binding,
        proofs,
    }
}

fn common_credential_root_raw_inputs(
    circuit_ref: ZkCircuitRef,
    slot: ZkCommonCredentialRootProofSlot,
    binding: ZkSessionBinding,
) -> Vec<u8> {
    let field_count = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 258,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus) => 192,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => 257,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => 292,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => 354,
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 129,
        _ => 0,
    };
    let mut fields = vec![0_u8; field_count * 32];
    let request_start = match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => 98,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootStatus)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage)
        | (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus)
        | (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => 0,
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => 64,
        _ => 0,
    };
    set_common_credential_root_request(&mut fields, request_start, binding);
    match (circuit_ref.family, circuit_ref.stage) {
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::RootAttestation) => {
            set_common_credential_root_u64(&mut fields, 96, 10);
            set_common_credential_root_u64(&mut fields, 97, 20);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::Lineage) => {
            set_common_credential_root_u64(&mut fields, 192, 20)
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::IssuerCredentialStatus) => {
            set_common_credential_root_u64(&mut fields, 160, 20);
            set_common_credential_root_u64(&mut fields, 225, 8);
            set_common_credential_root_u64(&mut fields, 291, 10);
        }
        (ZkCircuitFamily::CommonCredentialRootV1, ZkCircuitStage::PrivatePersonaClaim) => {
            set_common_credential_root_u64(&mut fields, 160, 20);
            set_common_credential_root_u32(&mut fields, 257, 1);
        }
        (ZkCircuitFamily::PrivatePersonaClaimV1, ZkCircuitStage::Session) => {
            set_common_credential_root_u64(&mut fields, 96, 20)
        }
        _ => {}
    }
    if matches!(
        slot,
        ZkCommonCredentialRootProofSlot::SelectedClaim0
            | ZkCommonCredentialRootProofSlot::SelectedClaim1
    ) {
        let (name, value) = if slot == ZkCommonCredentialRootProofSlot::SelectedClaim0 {
            ([3_u8; 32], 9_u8)
        } else {
            ([4_u8; 32], 10_u8)
        };
        set_common_credential_root_bytes32(&mut fields, 322, &name);
        fields[258 * 32 + 31] = value;
    }
    fields
}

fn set_common_credential_root_request(fields: &mut [u8], start: usize, binding: ZkSessionBinding) {
    set_common_credential_root_bytes32(fields, start, &binding.nonce_hash);
    set_common_credential_root_bytes32(fields, start + 32, &binding.audience_hash);
    set_common_credential_root_bytes32(
        fields,
        start + 64,
        &binding.transaction_data_public_input(),
    );
}

fn set_common_credential_root_bytes32(fields: &mut [u8], start: usize, value: &[u8; 32]) {
    for (position, byte) in value.iter().enumerate() {
        fields[(start + position) * 32 + 31] = *byte;
    }
}

fn set_common_credential_root_u64(fields: &mut [u8], index: usize, value: u64) {
    let start = index * 32 + 24;
    fields[start..start + 8].copy_from_slice(&value.to_be_bytes());
}

fn set_common_credential_root_u32(fields: &mut [u8], index: usize, value: u32) {
    let start = index * 32 + 28;
    fields[start..start + 4].copy_from_slice(&value.to_be_bytes());
}

include!("prepare_zk_presentation_common_credential_root_tests.rs");
