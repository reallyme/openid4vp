// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use crate::mdoc::{
    verify_mdoc_presentation, MdocCertificatePathValidation, MdocFormatErrorReason,
    MdocIssuerCertificateResolver, MdocPresentationVerificationInput,
};
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_to_vec, Algorithm, CoseSignatureAlgorithm,
};
use reallyme_crypto::dispatch::generate_keypair;
use reallyme_mdoc::{
    build_mdoc_device_response_cbor, build_mso_mdoc, BuildMdocDeviceResponseInput,
    CoseDeviceAuthSigner, CoseX5ChainIssuerAuthSigner, MdocElement, MdocIssueConfig, ValidityInfo,
};

struct EmptyResolver;

impl MdocIssuerCertificateResolver for EmptyResolver {
    fn validate_issuer_certificate_path(
        &self,
        _certificate_path_der: &[Vec<u8>],
        _mso_signing_time_unix: u64,
    ) -> Option<MdocCertificatePathValidation> {
        None
    }
}

struct TrustedCertificatePath {
    certificate_path_der: Vec<Vec<u8>>,
    issuer_public_key: Vec<u8>,
    not_before_unix: u64,
    not_after_unix: u64,
    iaca_not_before_unix: u64,
    iaca_not_after_unix: u64,
}

impl MdocIssuerCertificateResolver for TrustedCertificatePath {
    fn validate_issuer_certificate_path(
        &self,
        certificate_path_der: &[Vec<u8>],
        mso_signing_time_unix: u64,
    ) -> Option<MdocCertificatePathValidation> {
        (certificate_path_der == self.certificate_path_der.as_slice()
            && mso_signing_time_unix == 1_700_000_000)
            .then(|| MdocCertificatePathValidation {
                public_key: self.issuer_public_key.clone(),
                not_before_unix: self.not_before_unix,
                not_after_unix: self.not_after_unix,
                iaca_not_before_unix: self.iaca_not_before_unix,
                iaca_not_after_unix: self.iaca_not_after_unix,
            })
    }
}

#[test]
fn rejects_empty_device_response_before_identity_decode() {
    let result = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &[],
            session_transcript_cbor: &[0xa0],
            now_unix: 1_700_000_000,
        },
        &EmptyResolver,
    );
    assert!(result.is_err(), "empty DeviceResponse is rejected");
    let Err(err) = result else {
        return;
    };

    assert_eq!(err.reason(), MdocFormatErrorReason::InvalidDeviceResponse);
}

#[test]
fn rejects_empty_session_transcript_before_identity_verify() {
    let result = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &[0xa0],
            session_transcript_cbor: &[],
            now_unix: 1_700_000_000,
        },
        &EmptyResolver,
    );
    assert!(result.is_err(), "empty SessionTranscript is rejected");
    let Err(err) = result else {
        return;
    };

    assert_eq!(
        err.reason(),
        MdocFormatErrorReason::SessionTranscriptMismatch
    );
}

#[test]
fn presentation_input_debug_redacts_device_and_session_bytes() {
    let input = MdocPresentationVerificationInput {
        device_response_cbor: &[0xde, 0xad, 0xbe, 0xef],
        session_transcript_cbor: &[0xca, 0xfe, 0xba, 0xbe],
        now_unix: 1_700_000_000,
    };
    let debug = format!("{input:?}");

    assert!(!debug.contains("[222, 173, 190, 239]"));
    assert!(!debug.contains("[202, 254, 186, 190]"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn certificate_path_validation_debug_redacts_public_key_bytes() {
    let validation = MdocCertificatePathValidation {
        public_key: vec![0xde, 0xad, 0xbe, 0xef],
        not_before_unix: 1_699_999_999,
        not_after_unix: 1_700_000_001,
        iaca_not_before_unix: 1_699_999_999,
        iaca_not_after_unix: 1_800_000_000,
    };
    let debug = format!("{validation:?}");

    assert!(!debug.contains("[222, 173, 190, 239]"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn verifies_x5chain_mdoc_at_authenticated_signing_time() {
    const LEAF_CERTIFICATE_DER: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
    const SESSION_TRANSCRIPT_CBOR: &[u8] = &[0x83, 0xf6, 0xf6, 0x80];

    let (issuer_public_key, issuer_private_key) =
        generate_keypair(Algorithm::P256).expect("test P-256 issuer key generation succeeds");
    let (device_public_key, device_private_key) =
        generate_keypair(Algorithm::Ed25519).expect("test device key generation succeeds");
    let device_key = cose_key_to_vec(
        &cose_key_from_public_bytes(Algorithm::Ed25519, &device_public_key)
            .expect("test device COSE key builds"),
    )
    .expect("test device COSE key encodes");
    let certificate_path_der = vec![LEAF_CERTIFICATE_DER.to_vec()];
    let issuer_signer = CoseX5ChainIssuerAuthSigner {
        algorithm: CoseSignatureAlgorithm::Es256,
        private_key: &issuer_private_key,
        kid: None,
        x5chain_der: &certificate_path_der,
    };
    let device_signer = CoseDeviceAuthSigner {
        alg: Algorithm::Ed25519,
        private_key: &device_private_key,
        kid: None,
    };
    let validity_info = ValidityInfo {
        signed: 1_700_000_000,
        valid_from: 1_700_000_000,
        valid_until: 1_800_000_000,
        expected_update: None,
    };
    let config = MdocIssueConfig::new("org.iso.18013.5.1.mDL", validity_info, device_key.to_vec());
    let elements = vec![MdocElement {
        namespace: "org.iso.18013.5.1".to_owned(),
        element_identifier: "family_name".to_owned(),
        element_value_cbor: vec![0x63, b'D', b'O', b'E'],
        random: vec![7; 16],
    }];
    let (document, _) =
        build_mso_mdoc(&config, &elements, &issuer_signer).expect("test mdoc issuance succeeds");
    let response = build_mdoc_device_response_cbor(
        BuildMdocDeviceResponseInput {
            issuer_signed: document,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR.to_vec(),
            device_name_spaces_cbor: None,
            issuer_namespaces: None,
        },
        &device_signer,
    )
    .expect("test DeviceResponse builds");
    let resolver = TrustedCertificatePath {
        certificate_path_der,
        issuer_public_key,
        not_before_unix: 1_699_999_999,
        not_after_unix: 1_700_000_001,
        iaca_not_before_unix: 1_600_000_000,
        iaca_not_after_unix: 1_800_000_000,
    };

    let verified = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &response,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_001,
        },
        &resolver,
    )
    .expect("trusted x5chain mdoc verifies through OpenID4VP");
    assert_eq!(verified.document_count, 1);
    assert_eq!(verified.document_types, vec!["org.iso.18013.5.1.mDL"]);
    assert_eq!(verified.disclosed_claims.len(), 1);
    assert_eq!(verified.disclosed_claims[0].document_index, 0);
    assert_eq!(verified.disclosed_claims[0].namespace, "org.iso.18013.5.1");
    assert_eq!(
        verified.disclosed_claims[0].element_identifier,
        "family_name"
    );

    let invalid_window_resolver = TrustedCertificatePath {
        certificate_path_der: resolver.certificate_path_der.clone(),
        issuer_public_key: resolver.issuer_public_key.clone(),
        not_before_unix: 1_700_000_002,
        not_after_unix: 1_700_000_001,
        iaca_not_before_unix: resolver.iaca_not_before_unix,
        iaca_not_after_unix: resolver.iaca_not_after_unix,
    };
    let error = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &response,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_001,
        },
        &invalid_window_resolver,
    )
    .expect_err("an invalid certificate validity interval must fail closed");
    assert_eq!(
        error.reason(),
        MdocFormatErrorReason::InvalidIssuerAuthentication
    );

    let later_presentation = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &response,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_002,
        },
        &resolver,
    )
    .expect("a signer certificate valid at MSO signing remains valid for presentation");
    assert_eq!(later_presentation.document_count, 1);

    let expired_iaca_resolver = TrustedCertificatePath {
        certificate_path_der: resolver.certificate_path_der.clone(),
        issuer_public_key: resolver.issuer_public_key.clone(),
        not_before_unix: resolver.not_before_unix,
        not_after_unix: resolver.not_after_unix,
        iaca_not_before_unix: resolver.iaca_not_before_unix,
        iaca_not_after_unix: 1_700_000_001,
    };
    let error = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &response,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_002,
        },
        &expired_iaca_resolver,
    )
    .expect_err("the IACA must remain valid at presentation time");
    assert_eq!(
        error.reason(),
        MdocFormatErrorReason::InvalidIssuerAuthentication
    );

    let error = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: &response,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_001,
        },
        &EmptyResolver,
    )
    .expect_err("an untrusted certificate path must fail closed");
    assert_eq!(
        error.reason(),
        MdocFormatErrorReason::InvalidIssuerAuthentication
    );
}
