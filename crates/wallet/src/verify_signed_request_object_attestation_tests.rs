// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{
    key_resolver_with_attestation, signed_request_object_for, test_public_key, verifier,
    verifier_attestation_request, verify_signed_request_object, VerifiedVerifierAttestation,
    WalletErrorReason, WalletInvocationContext,
};

#[test]
fn rejects_verifier_attestation_jws_failure_from_jose_resolver() {
    let jwt = signed_request_object_for(&verifier_attestation_request());
    let verifier = verifier(key_resolver_with_attestation(Err(
        WalletErrorReason::InvalidVerifierAttestation,
    )));

    let err = verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        11,
    )
    .expect_err("attestation JWS validation failure is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}

#[test]
fn rejects_verifier_attestation_subject_from_jose_resolver() {
    let jwt = signed_request_object_for(&verifier_attestation_request());
    let attestation =
        VerifiedVerifierAttestation::new("other.example".to_owned(), None, test_public_key(), 100)
            .expect("test attestation evidence is valid");
    let verifier = verifier(key_resolver_with_attestation(Ok(attestation)));

    let err = verify_signed_request_object(
        &verifier,
        &jwt,
        &WalletInvocationContext::ProtocolTransport,
        11,
    )
    .expect_err("attestation subject binding is rejected");

    assert_eq!(err.reason(), WalletErrorReason::InvalidVerifierAttestation);
}
