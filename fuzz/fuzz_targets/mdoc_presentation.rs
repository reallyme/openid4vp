// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_formats::mdoc::{
    verify_mdoc_presentation, MdocCertificatePathValidation, MdocIssuerCertificateResolver,
    MdocPresentationVerificationInput,
};

const SESSION_TRANSCRIPT_CBOR: &[u8] = &[0x83, 0xf6, 0xf6, 0x80];

struct RejectingCertificateResolver;

impl MdocIssuerCertificateResolver for RejectingCertificateResolver {
    fn validate_issuer_certificate_path(
        &self,
        _certificate_path_der: &[Vec<u8>],
        _mso_signing_time_unix: u64,
    ) -> Option<MdocCertificatePathValidation> {
        None
    }
}

fuzz_target!(|data: &[u8]| {
    let _ = verify_mdoc_presentation(
        MdocPresentationVerificationInput {
            device_response_cbor: data,
            session_transcript_cbor: SESSION_TRANSCRIPT_CBOR,
            now_unix: 1_700_000_000,
        },
        &RejectingCertificateResolver,
    );
});
